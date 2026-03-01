# LSS Threshold Signing — Bug Fixes

This document describes the three bugs fixed to make the LSS threshold keygen and signing protocol work over libp2p, along with a brief explanation of the corrected design.

## Background

The LSS (Linear Secret Sharing) protocol implements 2-of-3 threshold ECDSA using additive secret sharing over libp2p. Keygen produces per-party `config.Config` values containing secret shares; signing uses those shares to collaboratively produce a signature without any single party holding the full private key.

The protocol uses the `luxfi/threshold` handler framework (`protocol.Handler` / `protocol.MultiHandler`), which drives each round by calling `Finalize()` and routing incoming messages to `VerifyMessage` / `StoreMessage` / `StoreBroadcastMessage`.

---

## Bug 1 — Premature Round Finalization (keygen and sign)

### Root Cause

Both `keygen/round1` and `sign/round1` are *broadcast-only* rounds: `MessageContent()` returns `nil` (no incoming P2P messages). The handler's `initializeRound` guard is:

```go
if r.MessageContent() != nil && !h.hasAllMessages(r) {
    return // defer finalization
}
```

Because `MessageContent() == nil`, the guard is bypassed, and `Finalize` is called after a fixed 20 ms sleep — regardless of whether the other `N-1` parties' broadcasts had arrived yet.

Additionally, `hasAllMessages` skips the broadcast-received check when `broadcasts[self]` is nil (i.e. before the local node has sent its own broadcast). So the check could never block for broadcasts.

### Effect

- `keygen/round1.Finalize` returned `round2` with an incomplete `allCommitments` map, causing `round2.VerifyMessage` to fail with `"missing commitments from sender"`.
- `sign/round1.Finalize` returned `round2` with an empty nonces map, causing `round2.Finalize` to fail with `"missing nonces from some signers"`.

### Fix — "Send once, return self until N" pattern

Each broadcast-only round now follows this pattern in `Finalize`:

1. **Generate local values once** — guarded by a nil/zero check so re-entrant calls are idempotent.
2. **Send broadcast once** — guarded by a `broadcastSent bool` flag.
3. **Return self** (`return r, nil`) if fewer than N entries are present in a `sync.Map` counter.
4. **Advance** — once all N entries are present, build the complete map and return the next round.

When `Finalize` returns `self`, the handler schedules a 10 ms retry, and each incoming broadcast message also triggers `tryAdvanceRound`. Eventually all N broadcasts arrive, the count reaches N, and the round advances with a fully-populated map.

---

## Bug 2 — CBOR Serialisation Failure (`curve.Point` / `curve.Scalar` in broadcast structs)

### Root Cause

The broadcast message structs originally declared fields with interface types:

```go
type broadcast1 struct {
    round.NormalBroadcastContent
    K curve.Point  // interface — CBOR cannot unmarshal into this
}

type broadcast2 struct {
    round.NormalBroadcastContent
    PartialSig curve.Scalar  // interface — same problem
}
```

CBOR encoding writes these as byte strings on the wire, but cannot unmarshal a byte string back into an interface value, producing:

```
cbor: cannot unmarshal byte string into Go struct field sign.broadcast1.K of type curve.Point
```

### Fix — Encode curve types as `[]byte`

Changed all broadcast/message structs to carry `[]byte` fields instead of interface types, mirroring the pattern already used in `keygen/round1.broadcast1.Commitments`:

```go
type broadcast1 struct {
    round.NormalBroadcastContent
    KBytes []byte  // MarshalBinary of curve.Point
}

type broadcast2 struct {
    round.NormalBroadcastContent
    PartialSigBytes []byte  // MarshalBinary of curve.Scalar
}
```

`Finalize` marshals the values before sending; `StoreBroadcastMessage` creates a fresh `r.Group().NewPoint()` / `r.Group().NewScalar()` and calls `UnmarshalBinary`.

---

## Bug 3 — Wrong `r`-Scalar Extraction and Mismatched Verification Equation

### Root Cause (r extraction)

The compressed binary encoding of a secp256k1 point is **33 bytes**: `[prefix(1)] + [x(32)]`. The original code computed:

```go
halfLen := len(rBytes) / 2  // = 16, not 32
xBytes  := rBytes[:halfLen] // first 16 bytes: prefix + 15 bytes of x — WRONG
```

This extracted garbled data instead of the 32-byte x-coordinate.

### Root Cause (verification equation mismatch)

The LSS partial-signature formula uses **additive nonce shares**:

```
s_i = k_i + r · λ_i · x_i · m
```

Summing over all signers:

```
S = k + r · x · m       (k = Σk_i,  x = Σλ_i·x_i)
```

The `ecdsa.Signature.Verify` method in the library implements a different (non-standard) ECDSA convention:

```
S·R = m·G + r·X   →   S = k · (m + r·x)   with R = k⁻¹·G
```

These two schemes are mathematically incompatible; the signature always failed verification.

### Fix

**r-scalar extraction** — replaced the manual byte slice with:

```go
r.rScalar = r.R.XScalar()
```

`XScalar()` correctly extracts the x-coordinate of a point as a scalar.

**Verification** — instead of calling `sig.Verify` (which uses the library's own convention and would break existing `pkg/ecdsa` tests), a standalone helper is defined in `sign/round3.go`:

```go
// verifyThreshold checks: s·G = R + (r·m)·X
func verifyThreshold(s curve.Scalar, R, X curve.Point, hash []byte) bool {
    group := X.Curve()
    r  := R.XScalar()
    m  := curve.FromHash(group, hash)
    sG := s.ActOnBase()
    rm := group.NewScalar().Set(r).Mul(m)
    return sG.Equal(R.Add(rm.Act(X)))
}
```

This matches the Schnorr-style equation satisfied by our additive scheme:

```
S·G = k·G + r·m·x·G = R + r·m·X   ✓
```

---

## Resulting Protocol Flow

### Keygen (3 rounds)

| Round | Sends | Waits for | Advances when |
|-------|-------|-----------|---------------|
| 1 | Commitment broadcast (polynomial evaluations as `[]byte`) | N broadcasts | All N commitment maps stored |
| 1→2 | P2P share to each other party (labelled `round=2`, buffered) | — | Sent in round1.Finalize |
| 2 | — | N−1 P2P shares | Handler calls Finalize once all are received |
| 3 | — | — | Immediate; computes and returns `*config.Config` |

### Signing (3 rounds)

| Round | Sends | Waits for | Advances when |
|-------|-------|-----------|---------------|
| 1 | Nonce commitment `KBytes` broadcast | N nonce broadcasts | All N stored in `receivedNonces` |
| 2 | Partial sig `PartialSigBytes` broadcast | N partial-sig broadcasts | All N stored in `receivedPartialSigs` |
| 3 | — | — | Immediate; combines sigs, runs `verifyThreshold`, returns `*ecdsa.Signature` |

All three parties produce the identical 65-byte Ethereum-format signature (same `R` and `S` because `S = Σs_i` is deterministic given the shared nonces and shares).
