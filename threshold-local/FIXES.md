# Threshold Library Handler Fixes

Local fork of `github.com/luxfi/threshold@v1.0.1` with fixes to `pkg/protocol/handler.go`.

Referenced from `go.mod` via:

```
replace github.com/luxfi/threshold => ./threshold-local
```

## Bug 1: Sign protocol deadlock at round 1

### Symptom

`cmp.Sign` hangs forever. All parties stuck at round 1 with every party (including self) listed as "missing" broadcasts. Keygen works fine.

### Root cause

`hasAllMessages()` checks whether the current round implements `BroadcastRound`, and if so, expects broadcast messages stored at the current round number. CMP Sign's `round1` implements `BroadcastRound` (returns `&broadcast2{}` from `BroadcastContent()`) but produces broadcasts with `RoundNumber=2`, not `1`. The handler stores the self-broadcast at round 2 but looks for it at round 1, never finding it.

Keygen doesn't hit this because its `round1` produces `broadcast1` with `RoundNumber=1`, so storage and lookup align.

### Fix

In `hasAllMessages()`, check if the self-broadcast exists at the current round number. If it doesn't, the round produced broadcasts for a different round number and doesn't need incoming broadcasts at its own number. Skip the broadcast wait.

Also added `go h.processQueuedMessages(nextRound.Number())` in the "already finalized" branch of `tryAdvanceRound` so that buffered round 2 messages get processed after the handler advances.

## Bug 2: Flaky "failed to validate affg proof" errors

### Symptom

`cmp.Sign` intermittently fails with "failed to validate affg proof for Delta MtA". One party aborts, sending a round-0 abort message that cascades to all others.

### Root cause

`verifyNormal()` and `verifyNormalForRound()` check that the sender's broadcast exists in the raw message store before verifying P2P messages, but don't check that `StoreBroadcastMessage` has actually been called to extract the broadcast data (K, G values) into the round's state. When a P2P message arrives before its corresponding broadcast is fully processed, `VerifyMessage()` fails because the round doesn't have the sender's cryptographic values yet.

### Fix

Added a `processedBroadcasts` check in both `verifyNormal()` and `verifyNormalForRound()`. P2P messages are only verified after the sender's broadcast has been fully processed.

## Bug 3: Batch processor contention

### Symptom

Contributes to message processing races. The batch processor and regular workers both read from `h.incoming`, causing non-deterministic message routing and delayed processing.

### Fix

Disabled batching in `NewMultiHandler` by setting `config.EnableBatching = false`.

## Changed functions

All changes in `pkg/protocol/handler.go`:

| Function | Change |
|---|---|
| `NewMultiHandler` | Disable batching |
| `tryAdvanceRound` | Process queued messages after advancing from an already-finalized round |
| `hasAllMessages` | Skip broadcast wait when self-broadcast is at a different round number |
| `verifyNormal` | Check `processedBroadcasts` before verifying P2P messages |
| `verifyNormalForRound` | Check `processedBroadcasts` before verifying P2P messages |
