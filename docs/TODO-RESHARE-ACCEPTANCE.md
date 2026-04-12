# Reshare Acceptance Test Plan

Tracks what reshare test coverage exists and what is still needed before
the feature is considered fully accepted.

## Implemented

### TSS Crypto Layer (`tss/tss_test.go`)

All run keygen → reshare → sign → verify with in-memory networks.

- [x] Same committee, same threshold (`TestReshareBasic`)
- [x] Same committee, threshold change (`TestReshareThresholdChange`)
- [x] Swap one member (`TestResharePartyChange`)
- [x] Grow committee 3→5 (`TestReshareGrowCommittee`)
- [x] Shrink committee 5→3 (`TestReshareShrinkCommittee`)
- [x] Full rotation, zero overlap (`TestReshareFullRotation`)
- [x] Chained reshares (`TestReshareChained`)

### Node Orchestration Unit Tests (`node/reshare_test.go`)

Mock KeyManager, no libp2p, no real FROST.

- [x] Job creation (`TestNode_CreateReshareJob`)
- [x] Job creation — new-only node (`TestNode_CreateReshareJob_NoKeys_NewOnlyNode`)
- [x] Job creation — no keys no old committee (`TestNode_CreateReshareJob_NoKeys_NoOldParties`)
- [x] `isKeyStale` logic (`TestNode_IsKeyStale`)
- [x] Defer membership event (`TestNode_DeferMembershipEvent`)
- [x] Defer — no job (`TestNode_DeferMembershipEvent_NoJob`)
- [x] Complete job — no deferred (`TestNode_CompleteReshareJob_NoDeferred`)
- [x] Complete job — with deferred, correct old/new parties (`TestNode_CompleteReshareJob_WithDeferred`)
- [x] Complete job — multiple deferred, sequential processing (`TestNode_CompleteReshareJob_MultipleDeferred`)
- [x] `applyMembershipEvent` pure function (`TestApplyMembershipEvent`)
- [x] Per-key register/complete/re-register (`TestNode_TryRegisterReshareKey`)
- [x] Channel signal on complete (`TestNode_CompleteReshareKey_SignalsWaiters`)
- [x] `runReshareSession` error closes channel (`TestNode_RunReshareSession_ErrorClosesChannel`)
- [x] Coordinator — no job (`TestNode_StartCoordinator_NoJob`)
- [x] Coordinator — duplicate (`TestNode_StartCoordinator_Duplicate`)

### Reshare Store (`node/reshare_store_test.go`)

- [x] Job CRUD lifecycle (`TestReshareStore_JobLifecycle`)
- [x] Key-done lifecycle (`TestReshareStore_KeyDoneLifecycle`)
- [x] Clear keys done — no group (`TestReshareStore_ClearKeysDone_NoGroup`)

### Integration Tests (`node/reshare_integration_test.go`)

Real libp2p + real FROST + real bbolt.

- [x] Shrink committee 4→3: keygen → reshare → verify sentinel on removed node → sign (`TestReshareIntegration_ShrinkCommittee`)
- [x] Grow committee 3→4: keygen → reshare → sign with new member (`TestReshareIntegration_GrowCommittee`)
- [x] On-demand reshare via sign path with committee change (`TestReshareIntegration_OnDemandViaSign`)
- [x] Job lifecycle state transitions (`TestReshareIntegration_JobLifecycle`)

### Design Decisions

- Same-committee reshare (proactive key refresh) is disabled. Reshare only triggers on
  membership changes via chain events. Will be re-enabled when operator key auth is
  implemented.
- `POST /v1/reshare` endpoint is disabled (commented out) pending operator key auth.
  Chain events auto-start the coordinator.
- `GET /v1/reshare/{group_id}` remains available for observability.

## TODO

### Integration Tests — Multi-Key

- [ ] **Coordinator loop with multiple keys**: keygen 3+ keys, create reshare job, start coordinator, verify all keys reshared and job transitions to ACTIVE.
- [ ] **Bounded concurrency**: verify semaphore limits concurrent reshare sessions in coordinator loop (may need timing assertions or mock delays).

### Integration Tests — Deferred Events

- [ ] **Chain-triggered deferred event**: simulate two rapid membership changes, verify first triggers reshare job, second is deferred, and deferred event processes after first completes with correct old/new parties.

### Integration Tests — Error & Recovery

- [ ] **Crash recovery**: create reshare job, kill/restart node, verify job reloaded from bbolt and reshare can resume.
- [ ] **Timeout / unreachable node**: one party goes offline mid-reshare. Verify 30s session timeout fires, error is reported, and the key channel is cleaned up so a retry can proceed.
- [ ] **Partial completion recovery**: reshare 2 of 5 keys, then coordinator restarts. Verify it resumes from key 3 (skips done keys).

### Integration Tests — Coord Protocol

- [ ] **Coord handler NACK for unknown group**: node without reshare job NACKs incoming msgReshare.
- [ ] **Coord handler idempotent ACK for done key**: re-sending msgReshare for an already-done key gets ACK without re-running protocol.
- [ ] **Coord handler NACK for duplicate session**: sending msgReshare while session already running for that key gets NACK.

### HTTP API

- [ ] **GET /v1/reshare/{group_id}**: verify status reporting (active, resharing, none).
- [ ] **POST /v1/reshare**: currently disabled. Re-enable with operator key auth (see below).

### Operator Key Auth

- [ ] **Operator key on-chain**: add `operatorAddress` field to factory or group contract, set at node registration.
- [ ] **Operator key validation**: admin endpoints (POST /v1/reshare, future admin ops) require signature from operator key, not the hot node identity key.
- [ ] **Re-enable same-committee reshare**: once operator key auth gates it, proactive key refresh can be safely exposed.

### Remote KMS

- [ ] **RemoteKeyManager.RunReshare**: currently returns error. Track Rust KMS reshare implementation and wire it up when available.

### Devnet / Harness

- [ ] **End-to-end with chain events**: anvil + factory + group contracts, add/remove node on-chain, verify reshare triggers automatically and signing works after.
- [ ] **Auth key integration**: generate auth keys as part of test harness setup (replaces old TestMode flow).
