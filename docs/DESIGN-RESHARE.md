# Reshare Protocol Design

Key resharing allows a signing group to rotate its membership (add or remove nodes,
change threshold) without changing the group public key. Existing signatures remain
valid; old key shares are cryptographically superseded.

---

## Table of Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Cryptographic protocol](#2-cryptographic-protocol)
3. [Roles and rounds](#3-roles-and-rounds)
4. [Group state machine](#4-group-state-machine)
5. [Storage](#5-storage)
6. [API](#6-api)
7. [Coord protocol](#7-coord-protocol)
8. [Node behavior](#8-node-behavior)
9. [tss layer design](#9-tss-layer-design)
10. [Edge cases](#10-edge-cases)
11. [Performance](#11-performance)

---

## 1. Goals and non-goals

**Goals**

- Support full committee rotation: new members, removed members, disjoint old/new sets, threshold changes
- Cryptographically invalidate old shares after reshare (removed party cannot sign)
- Group public key unchanged after reshare
- No downtime: sign requests on already-reshared keys proceed normally during a reshare in progress
- Explicit operator trigger: no automatic reshare; the application calls an API after changing membership on-chain
- Resumable: if the coordinator restarts mid-reshare, the job continues from where it left off

**Non-goals**

- Proactive refresh (same committee, periodic rotation for forward secrecy) — separate future concern
- Automatic reshare triggered by chain events — explicitly out of scope
- Concurrent reshares on the same group — serialized by design

---

## 2. Cryptographic protocol

Resharing uses the standard Lagrange-weighting technique (Herzberg et al. 1995). It is a
general Shamir secret sharing technique, not specific to FROST. The existing FROST key
shares are the inputs; the outputs are new FROST-compatible key shares for the new committee.

### Setup

Let:
- `oldParties` = current committee, size `n_old`, threshold `t_old`
- `newParties` = incoming committee, size `n_new`, threshold `t_new`
- `a` = the group secret (never reconstructed in the clear)
- `aᵢ` = old party `i`'s secret share, such that `Σᵢ λᵢ · aᵢ = a` (Lagrange reconstruction identity)
- `xⱼ` = numerical identifier of new party `j` (its `uint16` index in the new `PartyMap`)

### Round 1 — old parties: VSS distribution

Each old party `i`:

1. Compute Lagrange coefficient over the old committee:
   ```
   λᵢ = secret_sharing.DeriveInterpolatingValue(secp256k1, oldPartyNums, selfNum)
   ```

2. Compute Lagrange-weighted share:
   ```
   wᵢ = λᵢ · aᵢ     (scalar multiplication; aᵢ = keyShare.Secret)
   ```

3. Create a VSS polynomial `fᵢ(x)` of degree `(t_new - 1)` with constant term `wᵢ`:
   ```
   poly, commits = secret_sharing.ShardAndCommit(secp256k1, wᵢ, t_new, n_new)
   ```
   `commits[k] = fᵢ(k) · G` for `k ∈ [0, t_new-1]` (Feldman commitments)

4. Broadcast `commits` to all participants (old ∪ new).

5. For each new party `j`: send `fᵢ(xⱼ)` as a unicast P2P message.

### Round 2 — new parties: aggregate and publish

Each new party `j`, after receiving commits and evaluations from all `n_old` old parties:

1. Verify each received evaluation against its Feldman commitment:
   ```
   for each old party i:
     secret_sharing.Verify(secp256k1, xⱼ, fᵢ(xⱼ)·G, commits[i])
   ```
   Abort if any check fails.

2. Sum evaluations to get the new secret share:
   ```
   newSecretⱼ = Σᵢ fᵢ(xⱼ)
   ```

3. Broadcast new public key share:
   ```
   newPubShareⱼ = newSecretⱼ · G
   ```

### Round 3 — all parties: collect and verify

All participants (old ∪ new) collect all `n_new` public key shares and verify:

```
Σᵢ commits[i][0] == groupPubKey·G     (group key unchanged)
```

Each new party constructs its new `tss.Config`:
```go
newKeyShare = frost.NewKeyShare(frost.Secp256k1, selfNewNum, newSecretⱼ.Bytes(),
                                newPubShareⱼ.Encode(), groupKey)
```

`Config.Generation` is incremented by 1. Old-only parties (removed nodes) do not produce
a new Config; their participation ends after Round 1.

### Correctness sketch

For any threshold-sized subset `S` of new parties, their Lagrange reconstruction recovers `a`:

```
Σⱼ∈S μⱼ · newSecretⱼ
  = Σⱼ∈S μⱼ · Σᵢ fᵢ(xⱼ)
  = Σᵢ Σⱼ∈S μⱼ · fᵢ(xⱼ)    [linearity — valid because fᵢ is a polynomial]
  = Σᵢ fᵢ(0)
  = Σᵢ wᵢ
  = Σᵢ λᵢ · aᵢ
  = a                         [Lagrange reconstruction identity]
```

---

## 3. Roles and rounds

A party's role depends on its membership in old and new committees:

| Role         | Condition                              | Round 1     | Round 2     | Round 3     |
|--------------|----------------------------------------|-------------|-------------|-------------|
| Old-only     | in `oldParties`, not in `newParties`   | Send VSS    | Collect     | Collect + verify |
| New-only     | in `newParties`, not in `oldParties`   | Receive VSS | Send pubshare | Collect + build Config |
| Both         | in both                                | Send VSS    | Send pubshare | Collect + build Config |

All parties (old ∪ new) participate in the session and receive Round 1 broadcasts. This
ensures every participant can verify the group key invariant in Round 3.

Old-only parties do not produce a new `tss.Config`. Their local ReshareJob entry for the
key is marked done with a sentinel indicating "no new share" — they will not be signers
after reshare.

---

## 4. Group state machine

Each node maintains a per-group reshare state locally (in memory, backed by bbolt).
States are not coordinated across nodes — each node updates its own state independently
based on chain events and protocol completions.

```
ACTIVE ──────────────────────────────────────────────────────► ACTIVE
  │  chain event (add/remove)                                      ▲
  │                                                                 │
  ▼                                                                 │
RESHARING  ──► (coordinator runs job)  ──► all keys done ──────────┘
  │
  │  new chain event while resharing
  ▼
  enqueue event → process after current job completes
```

**ACTIVE**: normal operation; all keys fresh; signs and keygens proceed normally.

**RESHARING**: one or more keys are stale; no new membership changes processed; sign
requests on stale keys either wait (if reshare in flight for that key) or trigger
on-demand reshare; sign requests on already-reshared keys proceed normally.

Transitions are per-group. Multiple groups can be in different states simultaneously.

---

## 5. Storage

Two new bbolt buckets alongside the existing `keyshards` bucket, in the same
`keyshards.db` file.

### 5.1 `reshare_jobs` bucket

```
reshare_jobs/
  └─ <groupID>   →  JSON ReshareJob
```

```go
type ReshareJob struct {
    GroupID      string      `json:"group_id"`
    OldParties   []PartyID   `json:"old_parties"`
    NewParties   []PartyID   `json:"new_parties"`
    OldThreshold int         `json:"old_threshold"`
    NewThreshold int         `json:"new_threshold"`
    KeysTotal    []string    `json:"keys_total"`    // snapshot of all key IDs at job creation
    StartedAt    time.Time   `json:"started_at"`
    EventType    string      `json:"event_type"`    // "node_added" | "node_removed"
    DeferredEvents []DeferredMembershipEvent `json:"deferred_events,omitempty"`
}

type DeferredMembershipEvent struct {
    EventType  string    `json:"event_type"`   // "node_added" | "node_removed"
    NodeAddr   string    `json:"node_addr"`
    DetectedAt time.Time `json:"detected_at"`
}
```

One document per group. Written when membership event is detected. Deleted when all
keys are done. The `KeysTotal` field is a point-in-time snapshot: keys created after
the reshare starts are born into the new committee and do not need resharing.

`DeferredEvents` accumulates additional membership changes that arrive while resharing
is in progress. Processed sequentially after the current job completes.

### 5.2 `reshare_done` bucket

```
reshare_done/
  └─ <groupID>/
       └─ <keyID>  →  JSON ReshareKeyRecord
```

```go
type ReshareKeyRecord struct {
    CompletedAt time.Time `json:"completed_at"`
    ByNode      string    `json:"by_node"`      // PartyID of node that ran reshare
    OldOnly     bool      `json:"old_only"`     // true = this node is not in new committee
}
```

Written when a single key's reshare completes. One entry per key per group.
`KeysTotal - keys in reshare_done` = stale keys at any point.

On node restart: read ReshareJob to find the group is RESHARING; scan `reshare_done`
to find which keys are already complete; resume the coordinator (if this node was
coordinator) or simply re-enter participant mode for the remaining keys.

### 5.3 Stale key check

A key `(groupID, keyID)` is stale if and only if:
1. A `reshare_jobs/<groupID>` entry exists, AND
2. `keyID` is in `job.KeysTotal`, AND
3. No `reshare_done/<groupID>/<keyID>` entry exists.

This is a pure read — no locks needed beyond normal bbolt read transactions.

### 5.4 In-memory reshare state

The `Node` struct gains:

```go
reshareJobsMu sync.RWMutex
reshareJobs   map[string]*ReshareJob    // groupID → active job (nil if ACTIVE)

// Per-key reshare channels: sign handlers wait on these.
// Written by coordinator or on-demand initiator when reshare starts for a key;
// closed when it completes. Coordinator creates entries; non-coordinators
// create entries when they initiate on-demand reshares.
reshareKeysMu sync.Mutex
reshareKeys   map[reshareKeyID]chan struct{}  // (groupID,keyID) → done channel

// Per-group coordinator flag: true if this node is running the worker pool.
reshareCoordMu sync.Mutex
reshareCoord   map[string]bool  // groupID → isCoordinator
```

```go
type reshareKeyID struct {
    GroupID string
    KeyID   string
}
```

---

## 6. API

### `POST /v1/reshare`

Starts the background reshare job on this node, making it the coordinator for the group.

**Request:**

```json
{
  "group_id":    "0x...",
  "concurrency": 5
}
```

| Field         | Type   | Required | Default | Notes                                          |
|---------------|--------|----------|---------|------------------------------------------------|
| `group_id`    | string | yes      | —       | Group contract address (lower-cased)           |
| `concurrency` | int    | no       | 1       | Max parallel reshare sessions; capped at `max(1, 60/group_size)` |

**Responses:**

| Status | Meaning                                                       |
|--------|---------------------------------------------------------------|
| 200    | Reshare job started; body contains job summary               |
| 404    | Group not found or no reshare job pending (group is ACTIVE)  |
| 409    | Reshare already in progress on this node for this group      |
| 500    | Internal error                                               |

**200 body:**

```json
{
  "group_id":    "0x...",
  "keys_total":  1000,
  "keys_done":   47,
  "concurrency": 5,
  "status":      "started"
}
```

`keys_done` reflects progress already recorded in `reshare_done` (e.g. from a previous
run that was interrupted and is now being resumed).

---

### `GET /v1/reshare/:group_id`

Returns current reshare status for a group.

**Response:**

```json
{
  "group_id":    "0x...",
  "status":      "resharing",
  "keys_total":  1000,
  "keys_done":   312,
  "keys_stale":  688,
  "started_at":  "2026-03-28T10:00:00Z",
  "concurrency": 5,
  "is_coordinator": true
}
```

`status` is one of `"active"` (no pending job), `"resharing"` (job in progress),
`"none"` (group not known to this node).

`is_coordinator` is true if this node is currently running the worker pool.

---

## 7. Coord protocol

### New message type

Add `msgReshare coordMsgType = 3` to `node/coord.go`.

### Extended `coordMsg`

New fields appended to the existing struct (CBOR integer keys continue from 10):

```go
// Reshare fields (cbor keys 11–15)
OldParties    []tss.PartyID `cbor:"11,keyasint,omitempty"`
NewParties    []tss.PartyID `cbor:"12,keyasint,omitempty"`
NewThreshold  int           `cbor:"13,keyasint,omitempty"`
ReshareNonce  string        `cbor:"14,keyasint,omitempty"` // random, for session ID uniqueness
```

For `msgReshare`, the existing `GroupID`, `KeyID`, `Parties` (= old ∪ new), and
`Threshold` (= old threshold) fields are also populated. `ReshareNonce` allows
concurrent reshare attempts on the same key (by different initiators) to produce
distinct session IDs so the conflict is detectable.

### Session ID

```go
func reshareSessionID(groupID, keyID, nonce string) string {
    return groupID + ":reshare:" + keyID + ":" + nonce
}
```

This is distinct from `keygenSessionID` and `signSessionID`, preventing any accidental
session collision.

### Participant validation

On receiving `msgReshare`, a participant verifies before ACKing:

1. A `reshare_jobs/<groupID>` entry exists (i.e., this node has seen the membership event).
2. `msg.OldParties` matches `job.OldParties` (same old committee).
3. `msg.NewParties` matches `job.NewParties` (same new committee).
4. `msg.KeyID` is in `job.KeysTotal` and not yet in `reshare_done`.
5. This node is in `oldParties ∪ newParties` (otherwise it has no role).

If check 4 fails because the key is already done: send ACK but immediately complete
(no-op — handles the race where coordinator and on-demand initiator collide).

If any other check fails: NACK (write `0` byte to stream) and close.

Auth validation (JWT / ZK proof) is **not** applied to `msgReshare`. Reshare is an
administrative operation authorized by the API caller's network access, not by an
end-user credential.

---

## 8. Node behavior

### 8.1 Chain client — on membership event

`chain.go` handles `NodeActivatedInGroup` and `NodeDeactivatedInGroup` events.

On either event for group `G`:

```
1. Acquire reshareJobsMu.
2. If job exists for G (RESHARING):
   - Append event to job.DeferredEvents.
   - Persist updated job to reshare_jobs bucket.
   - Release lock; return (do not create a new job).
3. If no job (ACTIVE):
   - Enumerate all key IDs in keyshards/<G> → KeysTotal.
   - Determine OldParties (current chain members before event) and
     NewParties (current chain members after event).
   - Write ReshareJob to reshare_jobs/<G>.
   - Release lock.
   - Log: "reshare job created, N keys stale; call POST /v1/reshare to start"
```

The chain client does **not** start the coordinator goroutine. It only creates the job
and marks the group RESHARING. Signing on stale keys is blocked from this point.

### 8.2 Sign handler — stale key check

In `handleSign`, after resolving `keyID` and before loading the config, insert:

```
if isStale(groupID, keyID):
    waitForReshare(groupID, keyID)  // blocks until done channel closed
    // fall through to normal sign path with new config
```

`waitForReshare`:

```
1. Check reshareKeys[(groupID,keyID)]:
   a. Channel exists → wait on it (reshare already in progress, initiated by
      coordinator or another on-demand request).
   b. No channel:
      - Create channel, store in reshareKeys.
      - Initiate on-demand reshare (section 8.4).
      - Close channel when complete.
```

The sign handler then reloads the config (which now contains the new key share) and
proceeds normally.

### 8.3 Coordinator — `POST /v1/reshare` handler

```
1. Validate: group exists, reshare job exists (group is RESHARING), not already coordinating.
2. Set reshareCoord[groupID] = true.
3. Read job: KeysTotal, KeysDone (from reshare_done bucket), derive stale = total - done.
4. Report keys_done/keys_total in 200 response.
5. Launch background goroutine: coordinatorLoop(groupID, staleKeys, concurrency).
```

**coordinatorLoop:**

```
sem = make(chan struct{}, concurrency)  // semaphore

for each keyID in staleKeys:
    // Skip if another goroutine already finished it (on-demand race).
    if isDone(groupID, keyID): continue

    // If on-demand is already running for this key, wait for it rather
    // than launching a duplicate.
    if ch, exists := reshareKeys[(groupID,keyID)]; exists:
        wait on ch
        continue

    acquire sem slot
    register reshareKeys[(groupID,keyID)] channel

    go func(keyID):
        defer release sem slot
        defer close reshareKeys[(groupID,keyID)] channel

        err = runReshareSession(groupID, keyID, job)
        if err != nil:
            log error; backoff; retry up to 3 times
            if still failing: log "key stale, manual intervention may be required"
            return

        writeReshareKeyRecord(groupID, keyID)
        invalidateConfigCache(groupID, keyID)  // force reload from store on next sign

when all keys done:
    reshareCoord[groupID] = false
    delete reshare_jobs/<groupID>
    clear all reshare_done/<groupID> entries
    set group ACTIVE

    if job.DeferredEvents non-empty:
        process first deferred event: create new ReshareJob
        // application will need to call POST /v1/reshare again
        log "deferred membership event processed; call POST /v1/reshare to continue"
```

### 8.4 On-demand reshare (non-coordinator node)

Triggered from `waitForReshare` when no channel exists for `(groupID, keyID)`:

```
1. Read ReshareJob for groupID from store.
2. Generate reshareNonce (random 8 bytes, hex).
3. Run runReshareSession(groupID, keyID, job, nonce) — same function used by coordinator.
4. On success: writeReshareKeyRecord, invalidate cache.
5. On NACK from all participants (key already done by coordinator): treat as success,
   reload config from store.
```

`runReshareSession` is shared between coordinator and on-demand paths. The only
difference is the nonce (coordinator uses a deterministic one; on-demand uses random).

### 8.5 `runReshareSession`

```go
func (n *Node) runReshareSession(ctx context.Context, groupID, keyID string, job *ReshareJob) error {
    cfg, err := n.cachedConfig(groupID, keyID)  // load old config
    // cfg may be nil if this node is new-only (joining); that is valid.

    nonce = randomNonce()
    sessID = reshareSessionID(groupID, keyID, nonce)
    allParties = union(job.OldParties, job.NewParties)

    sn = network.NewSessionNetwork(ctx, n.host, sessID, allParties)
    defer sn.Close()

    broadcastCoord(ctx, allParties, coordMsg{
        Type:         msgReshare,
        GroupID:      groupID,
        KeyID:        keyID,
        Parties:      allParties,
        Threshold:    job.OldThreshold,
        OldParties:   job.OldParties,
        NewParties:   job.NewParties,
        NewThreshold: job.NewThreshold,
        ReshareNonce: nonce,
    })

    newCfg, err = runReshareOn(ctx, n.host, sn, sessID, cfg, job)
    // newCfg is nil if this node is old-only (not in new committee)

    if newCfg != nil:
        n.store.Put(groupID, keyID, newCfg)
        n.mu.Lock(); n.configs[shardKey{groupID,keyID}] = newCfg; n.mu.Unlock()

    return err
}
```

### 8.6 Coord handler for `msgReshare`

```
case msgReshare:
    1. Validate (section 7).
    2. If key already done: ACK, no-op goroutine, done.
    3. Check / register reshareKeys[(groupID,keyID)] channel.
       If already running: NACK (duplicate session — coordinator and on-demand race).
    4. Register SessionNetwork for sessID.
    5. ACK.
    6. go func():
         load old config (nil if new-only)
         newCfg, err = runReshareOn(...)
         if newCfg != nil: store.Put, update cache
         writeReshareKeyRecord
         close reshareKeys channel
```

---

## 9. tss layer design

### 9.1 `Reshare` function signature

```go
// ReshareParams holds the inputs to a reshare session.
type ReshareParams struct {
    SelfID       PartyID
    OldParties   []PartyID   // sorted; must contain at least threshold+1 parties
    NewParties   []PartyID   // sorted
    OldThreshold int
    NewThreshold int
    // OldConfig is this party's current key share. Nil if SelfID is new-only
    // (joining the group and has no prior share).
    OldConfig    *Config
}

// Reshare returns the starting Round for a key reshare session.
// The result value returned by Run is a *Config (new key share), or nil
// if SelfID is old-only (not in NewParties).
func Reshare(params ReshareParams) Round
```

### 9.2 Message payloads

```go
// reshareCommitPayload is the Round 1 broadcast from each old party.
// Contains Feldman VSS commitments for the new polynomial.
type reshareCommitPayload struct {
    // Commitments[k] = fᵢ(k)·G encoded, for k in [0, newThreshold-1]
    Commitments [][]byte `cbor:"c"`
}

// reshareEvalPayload is the Round 1 P2P message from each old party to each new party.
// Contains the polynomial evaluation for that new party's index.
type reshareEvalPayload struct {
    Evaluation []byte `cbor:"e"` // fᵢ(xⱼ) as scalar bytes
}

// resharePubSharePayload is the Round 2 broadcast from each new party.
// Contains the new party's public key share for collection by all parties.
type resharePubSharePayload struct {
    PubShare []byte `cbor:"p"` // newSecretⱼ·G encoded
}
```

### 9.3 Round structure

**`reshareRound1`** — all parties participate; old parties send, new-only parties only receive.

State held:
```go
type reshareRound1 struct {
    params      ReshareParams
    oldPartyMap map[PartyID]uint16  // old party → old numerical ID
    newPartyMap map[PartyID]uint16  // new party → new numerical ID (1-based, sorted)
    allParties  PartyIDSlice        // old ∪ new, sorted

    mu            sync.Mutex
    // Sent by self (if old party):
    poly          *secretsharing.Polynomial  // fᵢ(x)
    commitBytes   [][]byte                   // Feldman commitments
    broadcastSent bool
    evalsSent     bool

    // Received from old parties:
    commits   map[PartyID][]byte   // old partyID → encoded commitments
    myEval    []byte               // fᵢ(xⱼ) received from old party i (if new party)
    evalsRecv map[PartyID][]byte   // old partyID → my evaluation (indexed by sender)
}
```

`Finalize` logic:
- If old party and not yet computed: compute `wᵢ`, create polynomial, store commits.
- If not yet broadcast: emit Round 1 broadcast (commits) and Round 1 P2P messages (evals to each new party).
- Wait until: all old-party broadcasts received AND (if self is new party) own evaluation received from every old party.
- Advance to `reshareRound2`.

**`reshareRound2`** — new parties compute and broadcast public key shares. Old-only parties only collect.

State held:
```go
type reshareRound2 struct {
    params      ReshareParams
    newPartyMap map[PartyID]uint16
    allParties  PartyIDSlice

    // From round 1:
    commits   map[PartyID][][]byte  // old partyID → []commitment points
    evalsRecv map[PartyID][]byte    // old partyID → my evaluation scalar bytes

    mu            sync.Mutex
    newSecret     *ecc.Scalar      // Σᵢ fᵢ(xⱼ) — nil if old-only
    newPubShare   []byte           // newSecret·G encoded
    broadcastSent bool
    pubShares     map[PartyID][]byte  // new partyID → encoded pub share
}
```

`Finalize` logic:
- If new party and not yet computed: verify each eval against Feldman commits; sum evals.
- If new party and not yet broadcast: emit Round 2 broadcast (new pub key share).
- Wait until: all new-party broadcasts received.
- Advance to `reshareRound3`.

**`reshareRound3`** — all parties verify group key invariant; new parties build Config.

```go
type reshareRound3 struct {
    params      ReshareParams
    newPartyMap map[PartyID]uint16

    // From round 1:
    oldCommits  map[PartyID][][]byte  // for group key verification

    // From round 2:
    newSecret   *ecc.Scalar   // nil if old-only
    pubShares   map[PartyID][]byte
}
```

`Finalize` logic:
- Verify: `Σᵢ oldCommits[i][0]·G == groupPubKey` (constant terms of old VSS polynomials sum to group key).
- If old-only: return `(nil, nil, nil, nil)` — no new Config; Run returns nil result.
- Build new `tss.Config`:
  ```go
  newKeyShare = frost.NewKeyShare(frost.Secp256k1, selfNewNum,
                                  newSecret.Bytes(),
                                  newPubShare,
                                  oldConfig.GroupKey)
  newConfig = &Config{
      ID:              params.SelfID,
      Threshold:       params.NewThreshold,
      MaxSigners:      len(params.NewParties),
      Generation:      oldConfig.Generation + 1,  // 0 if new-only with no old config
      KeyShareBytes:   newKeyShare.Encode(),
      GroupKey:        oldConfig.GroupKey,         // unchanged
      Parties:         params.NewParties,
      PartyMap:        params.newPartyMap,
      PublicKeyShares: <encoded from pubShares in new party order>,
      ChainKey:        <SHA256 of sorted new party pubshares>,
      RID:             <SHA256 of ChainKey>,
  }
  ```
- Return `(nil, nil, newConfig, nil)`.

### 9.4 New-party `PartyMap` assignment

New parties need stable `uint16` identifiers for the new `frost.Configuration`. Assign
them by sorted order of `NewParties` (same as `BuildPartyMap` used in keygen):

```go
newPartyMap = BuildPartyMap(NewParties)
```

Old parties that remain in the new committee keep their new-committee index, not their
old-committee index. The FROST configuration is entirely defined by the new committee.

### 9.5 `runReshareOn` helper (in `tss/session.go` or a new `tss/reshare_runner.go`)

```go
func runReshareOn(ctx context.Context, host *network.Host, sn *network.SessionNetwork,
                  sessID string, params tss.ReshareParams) (*tss.Config, error) {
    startRound := tss.Reshare(params)
    result, err := tss.Run(ctx, startRound, sn)
    if err != nil {
        return nil, err
    }
    if result == nil {
        return nil, nil  // old-only party, no new config
    }
    return result.(*tss.Config), nil
}
```

---

## 10. Edge cases

### 10.1 Dual coordinator

Two operators call `POST /v1/reshare` on two different nodes simultaneously.

- Each node sets `reshareCoord[groupID] = true` and begins its worker pool.
- Both pools call `runReshareSession` for the same keys.
- For key K, both send `msgReshare` coord messages with different `ReshareNonce` values.
- Participants receive the first coord for K, register a session, ACK.
- Participants receive the second coord for K. The session is for a different `sessID`
  (different nonce). Participant checks `reshareKeys[(groupID,K)]`: channel already
  registered. NACK.
- The second coordinator's reshare session for K fails. It logs a warning and skips K
  (checks `isDone(groupID, K)` on retry — if first coordinator already finished K, it's
  marked done and skipped; otherwise, retry with new nonce).
- Both coordinators make forward progress; duplicate work for contested keys is at most
  one failed attempt. No correctness issue.

The 409 check on `POST /v1/reshare` prevents the dual-coordinator case on a single node
but cannot prevent it across nodes. The NACK-and-skip behavior provides safety.

### 10.2 Coordinator restart mid-reshare

On startup, `node.New` reads `reshare_jobs` from bbolt. For each job found:

1. Log: "found pending reshare job for group G, N keys remaining".
2. Reconstruct in-memory `reshareJobs[groupID]` from the stored job.
3. Do **not** automatically restart the coordinator goroutine — wait for `POST /v1/reshare`.

This means after a crash, the operator must call `POST /v1/reshare` again. The job
resumes from `keys_done` (already-completed keys are skipped). No key material is lost.

### 10.3 Insufficient old parties

`runReshareSession` sends coord to all `oldParties ∪ newParties`. If fewer than
`oldThreshold + 1` old parties ACK (or the session times out waiting for their Round 1
messages), the reshare fails.

Handling:
- Session times out (30s, same as keygen/sign).
- Coordinator logs error: "reshare failed for key K: need N old parties, got M".
- Retry up to 3 times with exponential backoff (1s, 4s, 16s).
- If all retries fail: log warning, skip key, continue with remaining keys.
  Key remains stale. Sign requests for it will get an error until a coordinator
  successfully reshares it (e.g., after the missing node comes back online and the
  operator calls `POST /v1/reshare` again).

### 10.4 Rapid successive membership changes (deferred events)

```
t=0: NodeA removed → ReshareJob created, coordinator starts
t=5s: NodeB removed while reshare still running
```

- Chain client sees NodeB event while `reshare_jobs/<G>` exists.
- Appends `DeferredMembershipEvent{NodeB, "node_removed"}` to job, persists.
- Current reshare continues to completion using the committee at t=0.
- When job completes: coordinator reads `DeferredEvents[0]`, creates a new ReshareJob
  for the NodeB removal, clears old job, logs notice for operator.
- Operator calls `POST /v1/reshare` again for the second event.

The new `OldParties` for the second job is the `NewParties` of the first job.

### 10.5 New-only party with no old config

A newly-added node participates in reshare as a receiver only. It has no entry in
`keyshards` for the key being reshared.

- `runReshareSession` loads config: `cfg = nil` (not found).
- `ReshareParams.OldConfig = nil`.
- In `reshareRound1.Finalize`: self is not in `OldParties`, skip send step, only collect.
- In `reshareRound2.Finalize`: compute new secret from received evals, broadcast pub share.
- In `reshareRound3.Finalize`: build new Config with `Generation = 1` (no prior generation).

### 10.6 On-demand race between coordinator and non-coordinator

- Coordinator is working through keys sequentially at N=1.
- A sign request arrives at a non-coordinator node for key K, which is still stale.
- Non-coordinator initiates on-demand reshare for K.
- Coordinator has not yet reached K in its queue.
- Both run `runReshareSession` with different nonces → one NACK'd (section 10.1 handling).
- The winner writes `reshare_done` and closes the channel.
- Coordinator, when it reaches K: sees `isDone(K)` is true, skips.
- Non-coordinator sign handler: channel closed, config cache invalidated, sign proceeds.

---

## 11. Performance

### Per-key estimate

Reshare is a 3-round interactive protocol with VSS math. Compared to keygen (3 rounds,
DKG), reshare involves similar message volume. Estimated at ~50ms per key on a 3-node
localhost cluster, based on keygen p50 of 36ms with overhead for Lagrange and Feldman
verification.

### Scale estimates

| Keys   | N=1 (sequential) | N=5   | N=20  |
|--------|-----------------|-------|-------|
| 1,000  | ~50s            | ~10s  | ~2.5s |
| 10,000 | ~8m             | ~1.7m | ~25s  |
| 100,000| ~1.4h           | ~17m  | ~4m   |
| 1,000,000| ~14h          | ~2.8h | ~42m  |

### Concurrency cap

To avoid saturating the group with concurrent sessions:

```go
maxConcurrency = max(1, 60/len(groupMembers))
```

| Group size | Cap |
|-----------|-----|
| 3         | 20  |
| 5         | 12  |
| 10        | 6   |
| 20        | 3   |

The requested `concurrency` in the API call is silently clamped to this cap.

### On-demand bypass

On-demand reshares (triggered by sign requests on non-coordinator nodes) are not subject
to the coordinator's semaphore. They run immediately and independently. The assumption
is that on-demand requests are sparse; if many keys are urgently needed simultaneously,
the coordinator should be run with high concurrency instead.

### Signing during reshare

Keys already in `reshare_done` can be signed immediately with their new shares. Only
keys still stale are blocked. For a group with many keys where reshare takes hours,
the vast majority of keys become available progressively as the coordinator works through
them.
