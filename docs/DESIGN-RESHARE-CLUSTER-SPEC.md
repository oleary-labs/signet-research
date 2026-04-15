# Reshare Cluster Spec

## Status: Draft

Companion doc to [DESIGN-RESHARE-HARDENING.md](DESIGN-RESHARE-HARDENING.md). Describes the system-wide formal model in [`specs/reshare/cluster.qnt`](../specs/reshare/cluster.qnt) — a multi-node Quint specification for reasoning about the hardening-doc invariants I1–I9.

## Why a cluster spec

The original lifecycle spec ([`specs/reshare/lifecycle.qnt`](../specs/reshare/lifecycle.qnt)) modeled a single node's view of the reshare state machine. That worked for verifying single-node bookkeeping (ACTIVE↔RESHARING transitions, stale key checks, deferred event chaining) but cannot express any of the hardening-doc invariants the most worth worrying about, all of which are fundamentally **cross-node** properties:

- **I1** (atomicity): all new-committee members commit, or none do
- **I2** (old shares as backup): old-committee members retain shares until verified complete
- **I6** (one reshare at a time): no overlapping group-level reshares
- **I7** (coordinator failover): the system survives a coordinator crash
- **I8** (deferred events don't outrun migration): no chained event begins until the prior is verified
- **I9** (chain is source of truth): every job traces back to a chain event

These need a model that has multiple nodes, distributed per-key state, partial-failure modes, and atomicity preconditions. `cluster.qnt` provides that.

## Architecture

```
cluster.qnt (system-wide, multi-node)
    │
    │  contains as internal abstractions
    ▼
lifecycle.qnt          reshare.qnt
(single-node view)     (FROST cryptographic protocol)
                  \      /
                   \    /
              KeyManager interface
              (node/keymanager.go)
```

`cluster.qnt` is the spec for hardening invariants. `lifecycle.qnt` is preserved as a single-node bookkeeping reference. `reshare.qnt` models the FROST rounds independently.

## What the cluster spec models

### State

- **Canonical chain state** (`var chain`): members, threshold, keys, event log. The source of truth for I9.
- **Per-node local state** (`var nodes: PartyID -> NodeLocalState`): each of N nodes (currently 4) tracks its own `alive`, `seenMembers`, `jobActive`, `job`, `shares`, `role`. Node views can diverge from the chain — that's the point.

### Per-node per-key share state

Five distinct states encode the key-migration lifecycle for a single (node, key) pair:

| State | Semantics |
|---|---|
| `NoShare` | Never had a share for this key (or was old-only and the sentinel drop fired) |
| `OldShare` | Has the committed share from before any in-progress reshare |
| `OldAndPending` | Both-committee node mid-reshare: still has old + uncommitted new |
| `OnlyPending` | New-only node mid-reshare: has only the uncommitted new share |
| `NewCommitted` | Has only the new committed share — verification has happened |

The crucial structural property is the **separation of pending from committed**. A pending share is held alongside (or instead of) the old share but is not yet active. Verification (atomic group commit) is what promotes pending to committed. This is exactly the I2 invariant the hardening doc cares about: old shares are retained until verified complete.

The Go implementation is moving toward the same model: the `KeyVersionStore` recently added to `local_keymanager.go` introduces `WritePending` / `CommitReshare` / `DiscardPendingReshare` / `RollbackReshare` operations, with archived historical versions for rollback. The spec's pending/committed distinction is the abstract version of that store layer.

### Reshare attempt outcomes

A reshare attempt is one Quint action with a nondeterministic outcome chosen by the simulator:

| Outcome | Effect on per-node state |
|---|---|
| `AttemptAllSucceed` | Every eligible new-committee node advances to `Pending` |
| `AttemptPartialFail(set)` | Listed nodes fail (stay pre-reshare); others advance |
| `AttemptAllFail` | No node advances; attempt can be retried |

The `step` action explores all three outcomes, so the model checks every partial-failure shape.

### Eligibility — the "must have a matching job view" rule

A node only participates in a reshare attempt if its local job has the **same `newParties` set** as the leader's job. This models the coord handler's ACK/NACK behavior: a node without a matching local job would NACK the coord message rather than silently accept share state. Without this rule, the leader could remotely mutate state on nodes that hadn't even polled the chain yet.

### Atomic commit

`commitKey` is the action that promotes pending shares to committed. Its precondition is the I1 atomicity guarantee at the action level:

```
Every node in the leader's local newParties must:
  (a) be alive
  (b) have an active job with the same newParties set
  (c) hold a pending share for k
```

If the precondition fails, `commitKey` does not fire. By construction, no partial commit is reachable: either the action runs and atomically transitions every new-committee member from pending to committed (and every old-only member from old to sentinel/`NoShare`), or it doesn't run at all.

This corresponds to the implementation's `CommitReshare` step: the pending bbolt entry is promoted to active, and the previous active version is archived for potential rollback.

### Rollback

`rollbackKey` is the action for cleaning up after a partial attempt that can't reach commit. Its precondition: at least one node has pending and **no node has committed yet**. Effect: every pending share is rolled back to its pre-attempt state (OldAndPending → OldShare, OnlyPending → NoShare). Old shares are preserved — this is I2 in action.

This corresponds to the implementation's `DiscardPendingReshare` and `RollbackReshare` operations.

### Crashes and failover

`crashNode` and `recoverNode` model node failures. A crashed node retains its share state (bbolt persistence) but its `alive` flag is false. Crashes can block a commit if they hit a new-committee member — the leader must wait for recovery. This is exactly the hardening-doc situation that needs operator escalation if all old∩new members crash.

### Deferred event chaining

`completeJob`'s deferred-event path captures the same fix from the Go code: when a deferred event is processed, the new job's `oldParties` is the previous job's `newParties` (the committee that actually holds the freshly committed shares), not the chain's current `members` (which may have additional later events applied).

## Invariants

| Invariant | Hardening I# | What it checks |
|---|---|---|
| `ownViewConsistent` | I1 | State-level sanity check that no node is in NewCommitted while another same-view peer is not. Backstop for the action-level commit atomicity. |
| `oldSharesRetained` | I2 | No initial-committee node has `NoShare` for a key unless a commit has happened (witnessed by some node holding `NewCommitted`). The protocol never drops an old share before commit. |
| `singleLeader` | I6 | At most one live node holds the `Leader` role at any state. |
| `jobTracesToChain` | I9 | Every active job's committee diff is non-empty only if the chain event log is non-empty. |
| `exclusiveShareStates` | structural | No node is simultaneously pending and committed for the same key. |

The combined `safety` invariant bundles all five.

**I1 is also enforced by construction** at the action level via `commitKey`'s precondition. The state-level `ownViewConsistent` is a backstop — it catches any future bug that could put the system in a partial-commit state through some path other than `commitKey`.

**I7 (failover)** is intentionally **not** in `safety`. Its precondition (`leaderPossible`) — at least one live node in old∩new — can be violated by simply crashing every intersection member. That's a system-level failure requiring operator intervention, not a protocol bug. The check is preserved as an auxiliary witness.

**I4 (no key left behind)** is enforced by the `completeJob` action: it only fires when `allLiveCommitted` holds across the new committee for every key in the snapshot.

**I8 (deferred events don't outrun)** is enforced by the structure of `completeJob`: deferred-event processing only happens after I4 holds for the current job.

## Witnesses (reachability checks)

| Witness | Verifies that... |
|---|---|
| `neverJobActive` | Nodes can enter an active job state |
| `neverFullyCommitted` | Keys can progress to NewCommitted across the new committee |
| `neverBackToIdleWithNewShares` | Jobs can complete and return to idle with new shares |
| `neverPartialPending` | Partial-failure attempts (some pending, some not) are reachable |
| `neverLeaderElected` | Leader election fires |

All five are reachable at depth 80 with 5000 samples.

## Validation results

```
quint typecheck specs/reshare/cluster.qnt        # clean
quint run … --max-steps=100 --max-samples=10000 --invariant=safety
[ok] No violation found
```

## The debugging journey

Three iterations of the spec found three real modeling bugs that exactly mirror potential implementation bugs. Each is worth understanding because they all map to concrete code paths.

### Bug 1: Non-member nodes creating jobs

**First failing invariant:** `leaderPossible`.

**Scenario:** node `n4` (not in the initial committee) polled the chain after a `RemoveNode` event, saw the new membership, and created a local job. But `n4` was not in either the old or new committee — it had no business creating a job at all.

**Real-system equivalent:** a chain client that creates `ReshareJob` rows for groups the node isn't actually a member of.

**Fix:** `nodeDetectEvent` only creates a job if the node is in `seenMembers` or `chain.members`. Non-participants update their local view but do nothing else. Verified by re-running `safety` after the fix.

### Bug 2: Cross-job state confusion

**Failing invariant:** `atomicCommit` (the original formulation).

**Scenario:** two nodes had differently-aged local jobs:
- `n3` polled the chain when membership was `{n2, n3}` (after `n1` removed) and ran a complete reshare to that committee. It now has `NewCommitted(k2)`.
- `n4` then joined the chain. It polled later when membership was `{n2, n3, n4}` and created a *new* job with that newer committee.
- From `n4`'s new-job perspective, `k2` looks "half-committed" because `n2` and `n3` already have it from the previous reshare, but `n4` doesn't.

This is not actually a partial commit — it's the tail of one completed reshare meeting the start of a new one. The model conflated "committed by any historical commit" with "committed by the current in-progress commit."

**Real-system equivalent:** any state-level invariant that doesn't track per-commit generation will hit this same false positive.

**Fix:** two parts.
1. When a node creates a new job via `nodeDetectEvent`, it relabels its own `NewCommitted` shares to `OldShare`. From the perspective of the new job, those shares are the "old" starting material.
2. Reframed atomicity as an **action-level** property enforced by `commitKey`'s precondition rather than a state invariant. The state-level `ownViewConsistent` is a weaker check that only fires for nodes with matching job views.

The deeper lesson: per-node multi-view state with a single global notion of "committed" is inherently ambiguous about epochs. A fully honest model would track generation numbers per commit. The current spec works around this by relabeling on new-job creation, which makes per-node views internally consistent.

### Bug 3: Dead nodes silently skipped during commit

**Failing invariant:** `safety` (intermittent, only at higher sample counts).

**Scenario:** the leader called `commitKey` while a new-committee member was crashed. The original `allLivePending` precondition treated dead nodes as "skipped" (`not(alive) or hasPending`), so the precondition passed even though the dead node had no pending share. `commitKey` then fired, transitioning live members to `NewCommitted` and leaving the dead member's state untouched. When the dead member recovered, it had `NoShare` while everyone else had `NewCommitted` — a real partial commit, exactly the I1 violation the hardening doc warns about.

**Real-system equivalent:** the implementation's current `msgReshareComplete` is fire-and-forget. If a participant is offline when the completion broadcast arrives, the coordinator will mark the key done while the offline participant has no pending state to commit. When that participant recovers, it's stale — and the coordinator already thinks the work is finished.

**Fix:** `allMembersAlivePending` requires every new-committee member to be `alive AND hasPending`. Dead nodes are not skipped — they actively block the commit, which is the correct behavior. The leader must wait for recovery (or for an operator to remove the dead node from the chain, which triggers a deferred event).

This is a meaningful finding for the implementation: `msgReshareComplete` should require explicit per-participant acknowledgment, not be fire-and-forget. The spec models the "wait for everyone" path; the code does not yet.

### Bug 4: Leaders mutating non-participating nodes

**Failing invariant:** `ownViewConsistent`.

**Scenario:** `n1` had no active job (hadn't yet detected the chain event). `n2` was Leader of a job with `newParties = {n1, n2, n4}` and called `attemptKeyReshare`. The original action updated `n1`'s share state because `n1` was alive and in `n2`'s new committee — even though `n1` had no local job.

**Real-system equivalent:** the coord handler running an attempt without first verifying the participant has a matching local job. The participant should NACK in that case, not silently accept the round messages.

**Fix:** `attemptKeyReshare` filters its eligible participants by:
1. `alive`
2. `jobActive`
3. `job.newParties == leader.job.newParties`

Same filter applied to `commitKey`. Now state changes only flow through nodes with matching local views.

This corresponds to the `auto-create reshare job on coord receive` change in the implementation (per the hardening doc's "Current State" section). The spec models the strict version (NACK if no matching view); the implementation is more lenient (auto-create a matching job from the coord message). Both are valid; the strict version is easier to verify.

## Mapping spec actions to implementation operations

| Cluster spec action | Implementation operation |
|---|---|
| `chainAddNode` / `chainRemoveNode` | `SignetGroup` contract emits `NodeJoined` / `NodeRemoved` |
| `nodeDetectEvent` | `chain.go` poll loop creates `ReshareJob` or appends to `DeferredEvents` |
| `electLeader` | `POST /v1/reshare` (currently API-triggered; hardening doc wants chain-driven leader election) |
| `attemptKeyReshare(_, _, AttemptAllSucceed)` | `LocalKeyManager.RunReshare` succeeding → `WritePending` |
| `attemptKeyReshare(_, _, AttemptPartialFail)` | Some participants persist pending, others time out / NACK |
| `commitKey` | `CommitReshare`: promote pending to active, archive previous version |
| `rollbackKey` | `DiscardPendingReshare` (no commit happened) or `RollbackReshare` (commit needs to be undone) |
| `crashNode` / `recoverNode` | Node process death + restart (bbolt survives) |
| `completeJob` | `coordinatorLoop` finishes all keys → `msgReshareComplete` broadcast (currently fire-and-forget) |

## Implementation gap analysis

The cluster spec captures the design the hardening doc is pushing toward. The current code is partially aligned. Here's where the spec is **ahead** of the implementation:

**Spec verified, implementation present:**
- Per-node share state (✓ via the new `KeyVersionStore` pending/active distinction)
- `WritePending` / `CommitReshare` / `DiscardPendingReshare` / `RollbackReshare` (✓)
- Chain event triggers reshare job creation (✓)
- Per-key reshare execution via leader (✓)

**Spec verified, implementation gap:**
- **Verified completion before commit.** The spec requires every new-committee member to acknowledge pending state before `commitKey` fires. The implementation's `msgReshareComplete` is fire-and-forget — it does not wait for participant ACKs. This is the most important gap: it allows the Bug 3 scenario in production.
- **Strict view matching.** The spec requires participants to have a matching `newParties` view before joining an attempt. The implementation auto-creates a job from the coord message, which is more lenient and may produce mixed-view states the spec rules out.
- **Leader election.** The spec models a single-leader role. The implementation has `POST /v1/reshare` as the trigger plus an auto-start on chain event — there is no failover protocol. Hardening doc Next Step item.

**Implementation present, spec doesn't model:**
- Generation tracking. The implementation tracks `Generation` in `tss.Config` and the new `KeyVersionStore` keys versions by generation. The spec elides this — it relabels rather than tracking generations. A future spec extension should add explicit generation numbers, which would also let `ownViewConsistent` become a stronger invariant.
- Atomic swap (`swapNode(old, new)`). Hardening doc proposes this; implementation hasn't added it; spec doesn't model it yet.
- bbolt crash recovery semantics. The spec models `crashNode` / `recoverNode` but treats the share state as cleanly persistent. The implementation has more nuanced behavior around interrupted writes.

## Limitations

- **Bounded model checking.** The spec is validated by simulation (10k samples × 100 steps), not exhaustive verification. Apalache exhaustive verification has not been run yet.
- **Small cluster.** 4 nodes, 2 keys — chosen to keep state space tractable. Properties verified at this size should generalize, but no proof.
- **No timing.** Quint is untimed. Timeout-driven escalation paths are not modeled.
- **No network model.** Messages are delivered atomically. Network partition is approximated via crashes.
- **No Byzantine behavior.** Honest-majority assumption.
- **Generation collapse.** As noted above, `NewCommitted` is rebound to `OldShare` on new-job creation rather than tracked as a distinct generation. This is a simplification that works for the current invariants but limits the strength of `ownViewConsistent`.

## Next steps

In rough priority order:

1. **Add explicit completion verification to the spec** — model `msgReshareComplete` as a per-participant ACK that must be collected before `completeJob` can fire. Then verify the implementation's fire-and-forget broadcast against this model — it should fail.
2. **Implement verified completion in the code** — fix the gap Bug 3 identifies. Either explicit ACKs from each new-committee member or a re-check round before declaring done.
3. **Add generation tracking to the spec** — promote share states to carry a generation number, so `ownViewConsistent` becomes a stronger state invariant.
4. **Model atomic swap** — add a `swapNode(old, new)` event type and verify that swap reshares preserve the same invariants as add+remove sequences.
5. **Apalache exhaustive verification** — run `quint verify` on the safety invariant once the spec is stable.
6. **Decide on `lifecycle.qnt`** — either delete it (cluster.qnt supersedes it for hardening-doc reasoning) or keep it as a single-node reference. Currently leaning toward keeping for documentation value.
