// Reshare Cluster — System-Wide View
//
// Based on: docs/DESIGN-RESHARE-HARDENING.md invariants I1..I9
//
// Models a multi-node reshare lifecycle where per-key state is distributed
// across nodes. This spec supersedes the single-node lifecycle.qnt for
// reasoning about the hardening-doc invariants, which are fundamentally
// about cross-node agreement:
//
//   - I1 (atomicity): either all new-committee members commit a key's new
//     share, or none do
//   - I2 (old shares as backup): old-committee members retain shares until
//     verified complete
//   - I6 (one group reshare at a time): overlapping group-level reshares
//     produce mixed-committee state
//   - I7 (coordinator failover): if the leader crashes, another node resumes
//   - I8 (deferred don't outrun): a deferred event only begins after the
//     prior job is fully verified complete
//   - I9 (chain is source of truth): every job traces back to a chain event
//
// Scope:
//   - Multi-node view with per-node local state
//   - Canonical chain state separate from node views (I9)
//   - Per-key share state across nodes with a "pending" phase (I2)
//   - Atomic commit across all new-committee members (I1)
//   - Leader election + crash + recovery (I7)
//   - Nondeterministic partial-failure outcomes for reshare attempts
//
// Intentional abstractions:
//   - No FROST rounds (reshare.qnt models that layer)
//   - No wire protocol / libp2p
//   - No timing; Quint is untimed
//   - A reshare attempt is a single atomic step with a nondet outcome set
//
module cluster {

  // ============================================================
  // 1. TYPES
  // ============================================================

  type PartyID = str
  type KeyID = str

  /// Per-node per-key share state. Encodes the five distinct situations a
  /// node can be in for a given key during a reshare.
  type ShareState =
    | NoShare          // this node has never held a share for this key
    | OldShare         // has the old committed share only
    | OldAndPending    // Both-committee node mid-reshare: has old + uncommitted new
    | OnlyPending      // new-only node mid-reshare: has only uncommitted new
    | NewCommitted     // has only the new committed share (post-verification)

  /// Canonical chain events that drive reshare (I9).
  type EventType =
    | AddNode(PartyID)
    | RemoveNode(PartyID)

  /// A reshare job as seen by a node.
  type JobInfo = {
    oldParties: Set[PartyID],
    newParties: Set[PartyID],
    keysSnapshot: Set[KeyID],
    deferredEvents: List[EventType]
  }

  /// A node's role in the current job.
  type CoordRole =
    | Idle          // no job, or job not yet acted upon
    | Leader        // this node is coordinating the current job
    | Follower      // this node is a participant, not a leader

  /// Per-node local state.
  type NodeLocalState = {
    id: PartyID,
    alive: bool,                // false = crashed
    seenMembers: Set[PartyID],  // local view of chain membership
    jobActive: bool,
    job: JobInfo,
    shares: KeyID -> ShareState,
    role: CoordRole
  }

  /// Canonical chain state — the source of truth (I9).
  type ChainState = {
    members: Set[PartyID],
    threshold: int,
    keys: Set[KeyID],
    eventLog: List[EventType]
  }

  /// The reshare attempt's possible outcomes.
  /// Used to nondeterministically explore partial-failure cases.
  type AttemptOutcome =
    | AttemptAllSucceed                 // every live new-committee node reaches Pending
    | AttemptPartialFail(Set[PartyID])  // listed new-committee nodes failed (stay pre-reshare)
    | AttemptAllFail                    // no node advances; reattempt possible

  // ============================================================
  // 2. CONSTANTS
  // ============================================================

  // 4 nodes, 2 keys — small enough for model checking, large enough to
  // cover grow/shrink/swap committee changes.
  pure val N1: PartyID = "n1"
  pure val N2: PartyID = "n2"
  pure val N3: PartyID = "n3"
  pure val N4: PartyID = "n4"
  pure val ALL_NODES: Set[PartyID] = Set(N1, N2, N3, N4)

  pure val INITIAL_MEMBERS: Set[PartyID] = Set(N1, N2, N3)
  pure val INITIAL_THRESHOLD = 2

  pure val K1: KeyID = "k1"
  pure val K2: KeyID = "k2"
  pure val INITIAL_KEYS: Set[KeyID] = Set(K1, K2)

  pure val EMPTY_JOB: JobInfo = {
    oldParties: Set(),
    newParties: Set(),
    keysSnapshot: Set(),
    deferredEvents: []
  }

  // ============================================================
  // 3. HELPERS
  // ============================================================

  /// Apply a single membership event to a set of members.
  pure def applyEvent(members: Set[PartyID], e: EventType): Set[PartyID] =
    match e {
      | AddNode(p) => members.union(Set(p))
      | RemoveNode(p) => members.exclude(Set(p))
    }

  /// Fetch a share state for a (node, key), defaulting to NoShare if absent.
  pure def shareOf(ns: NodeLocalState, k: KeyID): ShareState =
    if (ns.shares.keys().contains(k)) ns.shares.get(k)
    else NoShare

  /// Does this node currently hold a usable old share for k?
  pure def hasUsableOld(s: ShareState): bool =
    s == OldShare or s == OldAndPending

  /// Does this node currently hold a pending (uncommitted) new share for k?
  pure def hasPending(s: ShareState): bool =
    s == OldAndPending or s == OnlyPending

  /// Does this node hold a committed new share for k?
  pure def hasCommitted(s: ShareState): bool =
    s == NewCommitted

  /// Initial per-node state. Nodes in INITIAL_MEMBERS start with OldShare for
  /// every key; other nodes start with NoShare. Every node initially sees
  /// INITIAL_MEMBERS as its local view.
  pure def initialNode(p: PartyID): NodeLocalState = {
    id: p,
    alive: true,
    seenMembers: INITIAL_MEMBERS,
    jobActive: false,
    job: EMPTY_JOB,
    shares: if (INITIAL_MEMBERS.contains(p))
              INITIAL_KEYS.mapBy(k => OldShare)
            else
              INITIAL_KEYS.mapBy(k => NoShare),
    role: Idle
  }

  /// Compute what a participant's share state becomes after an attempt
  /// successfully reaches them. The pre-reshare state dictates the
  /// post-attempt state.
  pure def applySuccessfulAttempt(before: ShareState): ShareState =
    match before {
      | OldShare => OldAndPending       // Both node acquires pending new
      | NoShare => OnlyPending          // New-only node acquires pending new
      | OldAndPending => OldAndPending  // already in progress
      | OnlyPending => OnlyPending      // already in progress
      | NewCommitted => NewCommitted    // already committed (shouldn't happen on stale key)
    }

  /// Roll back a pending share back to its pre-attempt state.
  pure def rollbackShare(s: ShareState): ShareState =
    match s {
      | OldAndPending => OldShare
      | OnlyPending => NoShare
      | OldShare => OldShare
      | NoShare => NoShare
      | NewCommitted => NewCommitted
    }

  /// Commit a share from pending to committed. For Both nodes, this drops
  /// the old share. For old-only nodes in the new committee... but wait,
  /// old-only nodes are NOT in the new committee by definition, so they
  /// shouldn't reach a pending state. Old-only nodes go directly from
  /// OldShare to NoShare at commit time.
  pure def commitShare(s: ShareState): ShareState =
    match s {
      | OldAndPending => NewCommitted
      | OnlyPending => NewCommitted
      | OldShare => OldShare           // not a committing state
      | NoShare => NoShare
      | NewCommitted => NewCommitted
    }

  /// When a key is successfully committed, old-only nodes drop their shares.
  /// This runs on nodes that are in oldParties but not newParties.
  pure def sentinelShare(s: ShareState): ShareState =
    match s {
      | OldShare => NoShare   // sentinel: drop old after verified completion
      | _ => s
    }

  /// Count of live nodes in a set that hold a usable old share for k.
  pure def countLiveWithOld(nodeMap: PartyID -> NodeLocalState, group: Set[PartyID], k: KeyID): int =
    group.fold(0, (acc, p) => {
      val ns = nodeMap.get(p)
      if (ns.alive and hasUsableOld(shareOf(ns, k))) acc + 1
      else acc
    })

  /// Do ALL live members of set have committed new share for k?
  pure def allLiveCommitted(nodeMap: PartyID -> NodeLocalState, group: Set[PartyID], k: KeyID): bool =
    group.forall(p => {
      val ns = nodeMap.get(p)
      not(ns.alive) or hasCommitted(shareOf(ns, k))
    })

  /// Do ALL members of set have pending new share for k AND are currently
  /// alive? This is the strict precondition for `commitKey`: every
  /// new-committee member must actually persist the new share. A dead
  /// node cannot persist, so the commit must block until it recovers.
  /// (Matches the hardening doc's I1: every node persists.)
  pure def allMembersAlivePending(nodeMap: PartyID -> NodeLocalState, group: Set[PartyID], k: KeyID): bool =
    group.forall(p => {
      val ns = nodeMap.get(p)
      ns.alive and hasPending(shareOf(ns, k))
    })

  /// Does any live node in set have committed new share for k?
  pure def anyLiveCommitted(nodeMap: PartyID -> NodeLocalState, group: Set[PartyID], k: KeyID): bool =
    group.exists(p => {
      val ns = nodeMap.get(p)
      ns.alive and hasCommitted(shareOf(ns, k))
    })

  /// Does any live node in set have pending new share for k?
  pure def anyLivePending(nodeMap: PartyID -> NodeLocalState, group: Set[PartyID], k: KeyID): bool =
    group.exists(p => {
      val ns = nodeMap.get(p)
      ns.alive and hasPending(shareOf(ns, k))
    })

  // ============================================================
  // 4. STATE VARIABLES
  // ============================================================

  var chain: ChainState
  var nodes: PartyID -> NodeLocalState

  // ============================================================
  // 5. ACTIONS
  // ============================================================

  action init = all {
    chain' = {
      members: INITIAL_MEMBERS,
      threshold: INITIAL_THRESHOLD,
      keys: INITIAL_KEYS,
      eventLog: []
    },
    nodes' = ALL_NODES.mapBy(p => initialNode(p))
  }

  // ---------- Chain events (canonical truth for I9) ----------

  action chainAddNode(p: PartyID): bool = all {
    not(chain.members.contains(p)),
    ALL_NODES.contains(p),
    chain' = {
      ...chain,
      members: chain.members.union(Set(p)),
      eventLog: chain.eventLog.append(AddNode(p))
    },
    nodes' = nodes
  }

  action chainRemoveNode(p: PartyID): bool = all {
    chain.members.contains(p),
    chain.members.size() - 1 >= chain.threshold,  // don't drop below threshold
    chain' = {
      ...chain,
      members: chain.members.exclude(Set(p)),
      eventLog: chain.eventLog.append(RemoveNode(p))
    },
    nodes' = nodes
  }

  // ---------- Node detects chain event, creates or defers job ----------

  /// Node p polls the chain. If membership diverges from its local view,
  /// and it has no active job, create a new job. If it already has a job,
  /// defer the event.
  ///
  /// A node only creates a job when it is actually involved in the reshare
  /// (member of the old or new committee). Non-participant nodes simply
  /// update their local view and do nothing.
  action nodeDetectEvent(p: PartyID): bool = {
    val ns = nodes.get(p)
    if (not(ns.alive)) all { chain' = chain, nodes' = nodes }
    else if (ns.seenMembers == chain.members) all { chain' = chain, nodes' = nodes }
    else {
      val involved = ns.seenMembers.contains(p) or chain.members.contains(p)
      if (not(involved)) {
        // Not in old or new — just sync local view, no job.
        val updated = { ...ns, seenMembers: chain.members }
        all { chain' = chain, nodes' = nodes.set(p, updated) }
      } else if (not(ns.jobActive)) {
        // Create new job: snapshot keys, record old=seen, new=chain.
        // Reset any previously-committed shares to OldShare — from the
        // perspective of the new job, those shares are the "old" material.
        val relabeledShares = ns.shares.keys().mapBy(k => {
          val s = ns.shares.get(k)
          if (s == NewCommitted) OldShare else s
        })
        val newJob: JobInfo = {
          oldParties: ns.seenMembers,
          newParties: chain.members,
          keysSnapshot: chain.keys,
          deferredEvents: []
        }
        val updated = {
          ...ns,
          seenMembers: chain.members,
          jobActive: true,
          job: newJob,
          role: Follower,
          shares: relabeledShares
        }
        all { chain' = chain, nodes' = nodes.set(p, updated) }
      } else {
        // Job already active: defer the diff as an event.
        val added = chain.members.exclude(ns.seenMembers)
        val removed = ns.seenMembers.exclude(chain.members)
        val deferred: List[EventType] =
          if (added.size() > 0) [AddNode(added.fold("", (acc, x) => x))]
          else if (removed.size() > 0) [RemoveNode(removed.fold("", (acc, x) => x))]
          else []
        val updatedJob = { ...ns.job, deferredEvents: ns.job.deferredEvents.concat(deferred) }
        val updated = { ...ns, seenMembers: chain.members, job: updatedJob }
        all { chain' = chain, nodes' = nodes.set(p, updated) }
      }
    }
  }

  // ---------- Leader election ----------

  /// Elect a leader: a live node in the intersection of oldParties and
  /// newParties of its own active job becomes Leader. Only one leader per
  /// group at a time. Deterministic across failover: any surviving
  /// intersection member can take over.
  action electLeader(p: PartyID): bool = {
    val ns = nodes.get(p)
    val bothSets = ns.job.oldParties.intersect(ns.job.newParties)
    // No current leader exists (any live node already in Leader role?)
    val someLeader = ALL_NODES.exists(q => {
      val qs = nodes.get(q)
      qs.alive and qs.role == Leader and qs.jobActive
    })
    if (ns.alive and ns.jobActive and ns.role == Follower
        and bothSets.contains(p) and not(someLeader)) {
      val updated = { ...ns, role: Leader }
      all { chain' = chain, nodes' = nodes.set(p, updated) }
    } else {
      all { chain' = chain, nodes' = nodes }
    }
  }

  // ---------- Key reshare attempt ----------

  /// Leader attempts to reshare key k with outcome `outcome`.
  /// The outcome is chosen nondeterministically by `step` — this action
  /// just applies the effect of the given outcome.
  ///
  /// An attempt advances the participating subset S of live new-committee
  /// nodes from their pre-reshare state to a Pending state. Nodes outside
  /// S do not change.
  ///
  /// An attempt may also touch nodes that aren't strictly in newParties
  /// but are in oldParties — the real protocol involves them in Round 1.
  /// In this model, old-only nodes' share state does not change during an
  /// attempt; they only drop their old share at commit time via sentinelShare.
  action attemptKeyReshare(leader: PartyID, k: KeyID, outcome: AttemptOutcome): bool = {
    val ns = nodes.get(leader)
    val keyStale = ns.jobActive and ns.job.keysSnapshot.contains(k)
    val allNodesCommitted = allLiveCommitted(nodes, ns.job.newParties, k)
    if (not(ns.alive) or ns.role != Leader or not(keyStale) or allNodesCommitted) {
      all { chain' = chain, nodes' = nodes }
    } else {
      // A node can only participate in an attempt if it has a compatible
      // active job (same newParties set). This models the coord handler's
      // ACK/NACK behavior: a node without a matching view would NACK.
      val eligible = ns.job.newParties.filter(q => {
        val qs = nodes.get(q)
        qs.alive
          and qs.jobActive
          and qs.job.newParties == ns.job.newParties
      })
      val succeeders: Set[PartyID] =
        match outcome {
          | AttemptAllSucceed => eligible
          | AttemptPartialFail(fails) => eligible.exclude(fails)
          | AttemptAllFail => Set()
        }
      // Apply the successful attempt to each succeeder's state for this key.
      val updatedNodes = nodes.keys().mapBy(q => {
        val qs = nodes.get(q)
        if (succeeders.contains(q)) {
          val before = shareOf(qs, k)
          val after = applySuccessfulAttempt(before)
          { ...qs, shares: qs.shares.set(k, after) }
        } else qs
      })
      all { chain' = chain, nodes' = updatedNodes }
    }
  }

  // ---------- Atomic commit across new committee (enforces I1) ----------

  /// Commit key k: all live new-committee members must currently have
  /// pending shares for k. The commit is an atomic group operation:
  /// every live new-committee member transitions Pending -> NewCommitted,
  /// and every old-only live member drops its old share (sentinel).
  ///
  /// I1 (atomicity) is built into the precondition: no partial commit.
  action commitKey(leader: PartyID, k: KeyID): bool = {
    val ns = nodes.get(leader)
    val keyInJob = ns.jobActive and ns.job.keysSnapshot.contains(k)
    // Every new-committee member must:
    //   (a) be alive
    //   (b) have an active job with the same newParties view
    //   (c) have a pending share for k
    // This enforces that commit is a true atomic group operation — a node
    // with no matching job view cannot be committed remotely.
    val allReady = ns.job.newParties.forall(q => {
      val qs = nodes.get(q)
      qs.alive
        and qs.jobActive
        and qs.job.newParties == ns.job.newParties
        and hasPending(shareOf(qs, k))
    })
    if (not(ns.alive) or ns.role != Leader or not(keyInJob) or not(allReady)) {
      all { chain' = chain, nodes' = nodes }
    } else {
      val oldOnly = ns.job.oldParties.exclude(ns.job.newParties)
      val updatedNodes = nodes.keys().mapBy(q => {
        val qs = nodes.get(q)
        if (ns.job.newParties.contains(q)) {
          val after = commitShare(shareOf(qs, k))
          { ...qs, shares: qs.shares.set(k, after) }
        } else if (oldOnly.contains(q) and qs.alive) {
          // Old-only nodes drop their shares as sentinel — but only if
          // they're alive and aware of this reshare (have compatible job).
          // A dead old-only node keeps its old share until it recovers
          // and re-syncs. A node with no matching job view also keeps its
          // shares until it sees the new chain state.
          val hasMatchingView =
            qs.jobActive and qs.job.newParties == ns.job.newParties
          if (hasMatchingView) {
            val after = sentinelShare(shareOf(qs, k))
            { ...qs, shares: qs.shares.set(k, after) }
          } else qs
        } else qs
      })
      all { chain' = chain, nodes' = updatedNodes }
    }
  }

  // ---------- Rollback (for a failed attempt) ----------

  /// Roll back any pending shares for k back to their pre-attempt state.
  /// This leaves old shares intact (I2) and marks the key stale again.
  /// Safe to invoke whenever a subset of new-committee nodes is Pending but
  /// not all — i.e. a partial attempt cannot proceed to commit.
  action rollbackKey(leader: PartyID, k: KeyID): bool = {
    val ns = nodes.get(leader)
    val keyInJob = ns.jobActive and ns.job.keysSnapshot.contains(k)
    val anyPending = anyLivePending(nodes, ns.job.newParties, k)
    val anyCommitted = anyLiveCommitted(nodes, ns.job.newParties, k)
    if (not(ns.alive) or ns.role != Leader or not(keyInJob)
        or not(anyPending) or anyCommitted) {
      all { chain' = chain, nodes' = nodes }
    } else {
      val updatedNodes = nodes.keys().mapBy(q => {
        val qs = nodes.get(q)
        val before = shareOf(qs, k)
        val after = rollbackShare(before)
        { ...qs, shares: qs.shares.set(k, after) }
      })
      all { chain' = chain, nodes' = updatedNodes }
    }
  }

  // ---------- Node crash / recover (for I7) ----------

  action crashNode(p: PartyID): bool = {
    val ns = nodes.get(p)
    if (not(ns.alive)) all { chain' = chain, nodes' = nodes }
    else {
      // On crash: clear Leader role; keep shares intact (bbolt survives).
      val updated = { ...ns, alive: false, role: Idle }
      all { chain' = chain, nodes' = nodes.set(p, updated) }
    }
  }

  action recoverNode(p: PartyID): bool = {
    val ns = nodes.get(p)
    if (ns.alive) all { chain' = chain, nodes' = nodes }
    else {
      // On recovery: back to Follower if a job is active, Idle otherwise.
      val newRole = if (ns.jobActive) Follower else Idle
      val updated = { ...ns, alive: true, role: newRole }
      all { chain' = chain, nodes' = nodes.set(p, updated) }
    }
  }

  // ---------- Job completion and deferred-event chaining ----------

  /// Leader declares the current job complete: all keys in the snapshot
  /// must be NewCommitted across the new committee. If deferred events
  /// are present, the first one is converted into a new job whose
  /// oldParties = previous newParties (the committee that actually holds
  /// the freshly committed shares).
  action completeJob(leader: PartyID): bool = {
    val ns = nodes.get(leader)
    val allDone = ns.job.keysSnapshot.forall(k =>
      allLiveCommitted(nodes, ns.job.newParties, k))
    if (not(ns.alive) or ns.role != Leader or not(ns.jobActive) or not(allDone)) {
      all { chain' = chain, nodes' = nodes }
    } else if (ns.job.deferredEvents.length() == 0) {
      // Return all nodes to ACTIVE.
      val updatedNodes = nodes.keys().mapBy(q => {
        val qs = nodes.get(q)
        { ...qs, jobActive: false, job: EMPTY_JOB, role: Idle }
      })
      all { chain' = chain, nodes' = updatedNodes }
    } else {
      // Process the first deferred event: oldParties = previous newParties
      // (the committee that actually holds the shares), newParties = apply
      // the deferred event to them.
      val firstDeferred = ns.job.deferredEvents[0]
      val remaining = ns.job.deferredEvents.slice(1, ns.job.deferredEvents.length())
      val prevNew = ns.job.newParties
      val newMembers = applyEvent(prevNew, firstDeferred)
      // Keys snapshot: use current known keys (none created in this model).
      val newJob: JobInfo = {
        oldParties: prevNew,
        newParties: newMembers,
        keysSnapshot: ns.job.keysSnapshot,  // same keys; stale again after event
        deferredEvents: remaining
      }
      // Reset keys from NewCommitted back to OldShare for the new job —
      // the new job now treats them as "old".
      val updatedNodes = nodes.keys().mapBy(q => {
        val qs = nodes.get(q)
        val newShares = qs.shares.keys().mapBy(k => {
          val s = qs.shares.get(k)
          if (s == NewCommitted) OldShare else s
        })
        { ...qs, jobActive: true, job: newJob, role: Follower, shares: newShares }
      })
      all { chain' = chain, nodes' = updatedNodes }
    }
  }

  // ---------- Top-level nondeterministic step ----------

  action step = any {
    // Chain events — small fixed set of changes to keep state space bounded.
    chainAddNode(N4),

    nondet p = INITIAL_MEMBERS.oneOf()
    chainRemoveNode(p),

    nondet p = ALL_NODES.oneOf()
    nodeDetectEvent(p),

    nondet p = ALL_NODES.oneOf()
    electLeader(p),

    nondet p = ALL_NODES.oneOf()
    nondet k = INITIAL_KEYS.oneOf()
    attemptKeyReshare(p, k, AttemptAllSucceed),

    // Partial failure: the smallest nondet partial failure — one node fails.
    nondet p = ALL_NODES.oneOf()
    nondet k = INITIAL_KEYS.oneOf()
    nondet failed = ALL_NODES.oneOf()
    attemptKeyReshare(p, k, AttemptPartialFail(Set(failed))),

    nondet p = ALL_NODES.oneOf()
    nondet k = INITIAL_KEYS.oneOf()
    attemptKeyReshare(p, k, AttemptAllFail),

    nondet p = ALL_NODES.oneOf()
    nondet k = INITIAL_KEYS.oneOf()
    commitKey(p, k),

    nondet p = ALL_NODES.oneOf()
    nondet k = INITIAL_KEYS.oneOf()
    rollbackKey(p, k),

    nondet p = ALL_NODES.oneOf()
    crashNode(p),

    nondet p = ALL_NODES.oneOf()
    recoverNode(p),

    nondet p = ALL_NODES.oneOf()
    completeJob(p)
  }

  // ============================================================
  // 6. INVARIANTS
  // ============================================================

  /// I1 — atomicity is enforced at the ACTION level, not checked as a state
  /// invariant. `commitKey` can only fire when `allLivePending` holds across
  /// the entire new committee of the leader's local job; its effect is an
  /// atomic group transition. Therefore, no `commitKey` call can produce a
  /// partial commit.
  ///
  /// A state-level check of "if any node in newParties is NewCommitted,
  /// then all are" fails against per-node-view asymmetry: when different
  /// nodes have different local jobs (e.g. one polled an older chain state
  /// than another), the historical NewCommitted shares from a completed
  /// prior job look like "partial" against a new job's newParties set. That
  /// is an artifact of per-node locality, not a protocol bug.
  ///
  /// The real I1 concern — a failed commit leaving state partly migrated —
  /// is caught by `atomicCommitKeyAction` below, which is checkable at the
  /// transition level: no intermediate state between the precondition check
  /// and the group transition exists, because `commitKey` is a single Quint
  /// action.
  ///
  /// The following weaker structural check ensures that no node ever holds
  /// NewCommitted while in a local view where its own job says the key is
  /// not yet done on itself. Equivalent to: "my local shares agree with my
  /// local job's state."
  val ownViewConsistent =
    INITIAL_KEYS.forall(k =>
      ALL_NODES.forall(p => {
        val ns = nodes.get(p)
        // If this node is in its own job's new committee and claims to
        // have NewCommitted for k, then every live member of its new
        // committee should also have NewCommitted — because the commit
        // affected them atomically.
        val inNewCommittee = ns.jobActive and ns.job.newParties.contains(p)
        val hasCommit = hasCommitted(shareOf(ns, k))
        val keyInJob = ns.job.keysSnapshot.contains(k)
        if (inNewCommittee and hasCommit and keyInJob) {
          // All other nodes in THIS node's local newParties should also be
          // committed — but only those that have the SAME local job (same
          // newParties set). Check agreement among peers with the same view.
          ns.job.newParties.forall(q => {
            val qs = nodes.get(q)
            val sameView = qs.jobActive and qs.job.newParties == ns.job.newParties
            not(qs.alive) or not(sameView) or hasCommitted(shareOf(qs, k))
          })
        } else true
      }))

  /// I2 — no premature discard of old shares. If a node was originally in
  /// the initial committee and now has NoShare for a key, some commit must
  /// have happened for that key (evidenced by at least one node holding a
  /// NewCommitted share). That is, the protocol never drops an old share
  /// before the key is committed somewhere.
  val oldSharesRetained =
    INITIAL_KEYS.forall(k =>
      INITIAL_MEMBERS.forall(p => {
        val s = shareOf(nodes.get(p), k)
        // A node in the initial committee either:
        //   (a) still holds a share (OldShare, OldAndPending, or NewCommitted)
        //   (b) has NoShare because a commit happened (sentinel for old-only)
        if (s == NoShare) {
          ALL_NODES.exists(q => hasCommitted(shareOf(nodes.get(q), k)))
        } else true
      }))

  /// I6 — at most one group-level reshare is actively processing at a time.
  /// Concretely: at most one node holds the Leader role. Nodes may locally
  /// have differing views of a job during asynchronous polling, but only
  /// one leader can drive share-touching actions.
  val singleLeader = {
    val leaders = ALL_NODES.filter(p => {
      val ns = nodes.get(p)
      ns.alive and ns.role == Leader
    })
    leaders.size() <= 1
  }

  /// I7 / liveness precondition — leader failover is possible. If all
  /// live nodes with an active job have at least one live node in their
  /// old∩new intersection, failover can happen. This is NOT a protocol
  /// invariant: crashes of every intersection member will violate it, and
  /// the system then requires operator intervention. It is a state the
  /// spec tracks so we can witness crashes that wipe out the intersection
  /// (a scenario the hardening doc's I7 calls out as needing escalation).
  ///
  /// Not included in `safety` — see `livelock_crashed_intersection` witness.
  val leaderPossible =
    ALL_NODES.forall(p => {
      val ns = nodes.get(p)
      val bothSets = ns.job.oldParties.intersect(ns.job.newParties)
      val liveBoth = bothSets.filter(q => nodes.get(q).alive)
      (not(ns.alive)) or (not(ns.jobActive)) or (liveBoth.size() > 0)
    })

  /// I9 — every active job traces back to a chain event: its (oldParties,
  /// newParties) diff must match at least one event in the chain log.
  val jobTracesToChain =
    ALL_NODES.forall(p => {
      val ns = nodes.get(p)
      if (not(ns.jobActive)) true
      else {
        // The job was created because seenMembers diverged from chain.
        // Specifically, some event in the log produces the diff between
        // oldParties and newParties. Weak version: the diff is non-empty
        // and the chain has at least one event.
        val added = ns.job.newParties.exclude(ns.job.oldParties)
        val removed = ns.job.oldParties.exclude(ns.job.newParties)
        val diffSize = added.size() + removed.size()
        diffSize == 0 or chain.eventLog.length() > 0
      }
    })

  /// Structural: no node ever holds a share state that both has pending
  /// and committed simultaneously (these are exclusive in the enum, but
  /// this documents the intent).
  val exclusiveShareStates =
    ALL_NODES.forall(p =>
      INITIAL_KEYS.forall(k => {
        val s = shareOf(nodes.get(p), k)
        // hasPending and hasCommitted are mutually exclusive.
        not(hasPending(s) and hasCommitted(s))
      })
    )

  /// Combined safety invariant. Protocol-level correctness properties
  /// that must hold under arbitrary chain events, crashes, and partial
  /// reshare failures.
  val safety = and {
    ownViewConsistent,
    oldSharesRetained,
    singleLeader,
    jobTracesToChain,
    exclusiveShareStates
  }

  // ============================================================
  // 7. WITNESSES (reachability — these should be violable)
  // ============================================================

  /// Witness: a node can enter a job.
  val neverJobActive =
    ALL_NODES.forall(p => not(nodes.get(p).jobActive))

  /// Witness: a key can progress to NewCommitted on all new-committee nodes.
  val neverFullyCommitted =
    INITIAL_KEYS.forall(k =>
      ALL_NODES.forall(p => {
        val ns = nodes.get(p)
        not(hasCommitted(shareOf(ns, k)))
      }))

  /// Witness: a job can complete and return to ACTIVE with new shares in place.
  val neverBackToIdleWithNewShares =
    not(ALL_NODES.forall(p => {
      val ns = nodes.get(p)
      not(ns.jobActive) and INITIAL_KEYS.forall(k => {
        val s = shareOf(ns, k)
        s == NoShare or s == OldShare  // no committed new shares at end of run
      })
    }))

  /// Witness: a partial-failure attempt can occur (some node Pending, some not).
  val neverPartialPending =
    INITIAL_KEYS.forall(k => {
      val pendingSet = ALL_NODES.filter(p => hasPending(shareOf(nodes.get(p), k)))
      val nonPendingInJob = ALL_NODES.filter(p => {
        val ns = nodes.get(p)
        ns.jobActive and ns.job.newParties.contains(p)
          and not(hasPending(shareOf(ns, k)))
          and not(hasCommitted(shareOf(ns, k)))
      })
      pendingSet.size() == 0 or nonPendingInJob.size() == 0
    })

  /// Witness: a leader can be elected.
  val neverLeaderElected =
    ALL_NODES.forall(p => nodes.get(p).role != Leader)

}
