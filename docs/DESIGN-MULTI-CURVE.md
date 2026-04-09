# Multi-Curve Support: secp256k1 + Ed25519

Design notes for extending Signet to support FROST threshold signing over multiple
elliptic curves, enabling native signing for both EVM chains (secp256k1) and Solana
(Ed25519).

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Design principles](#2-design-principles)
3. [Target chain model](#3-target-chain-model)
4. [Rust KMS changes](#4-rust-kms-changes)
5. [Storage](#5-storage)
6. [gRPC schema changes](#6-grpc-schema-changes)
7. [Go node changes](#7-go-node-changes)
8. [API surface](#8-api-surface)
9. [Contract layer](#9-contract-layer)
10. [Solana program](#10-solana-program)
11. [Future curves](#11-future-curves)

---

## 1. Motivation

Signet currently targets EVM chains using FROST over secp256k1. To support Solana as a
first-class target, we need Ed25519 threshold signing. FROST is curve-agnostic by design
(RFC 9591), and the ZF FROST crate already ships official ciphersuites for both curves:

- `frost-secp256k1` (current)
- `frost-ed25519` (to add)

Solana natively supports Ed25519 signature verification via the `Ed25519SigVerify`
precompile (a syscall, essentially free). There is no need to verify Ed25519 signatures
on EVM, and no need to verify secp256k1 signatures on Solana. Each curve maps to its
target chain ecosystem.

---

## 2. Design principles

- **Curve is a group-level property.** Set at keygen time, immutable for the lifetime
  of the group. All members of a group use the same curve.
- **Target chain follows from curve.** secp256k1 groups target EVM chains; Ed25519
  groups target Solana. The node routes signing results to the appropriate chain.
- **KMS is the universal layer.** The KMS handles both ciphersuites and does not care
  about target chains. It just does FROST math on the requested curve.
- **Contract layer stays scoped.** EVM contracts only manage secp256k1 groups.
  Solana programs only manage Ed25519 groups. Neither needs to understand the other.
- **No cross-curve complexity.** A group never changes curves. Reshare stays
  within-curve. There is no need for curve conversion or cross-curve key derivation.

---

## 3. Target chain model

```
                          ┌─────────────────────────┐
                          │       signetd node       │
                          │                          │
                          │  ┌─────────┐ ┌────────┐ │
                          │  │secp256k1│ │Ed25519 │ │
                          │  │ groups  │ │ groups │ │
                          │  └────┬────┘ └───┬────┘ │
                          │       │          │      │
                          └───────┼──────────┼──────┘
                                  │          │
                    ┌─────────────┘          └──────────────┐
                    ▼                                       ▼
          ┌─────────────────┐                    ┌──────────────────┐
          │   EVM chains    │                    │      Solana      │
          │                 │                    │                  │
          │ SignetFactory    │                    │  Signet program  │
          │ SignetGroup      │                    │  Ed25519SigVerify│
          │ ecrecover/Schnorr│                    │  (native syscall)│
          └─────────────────┘                    └──────────────────┘
```

A node can participate in groups of either curve simultaneously. The libp2p network,
session management, and KMS bridging are curve-agnostic — only the crypto and chain
verification layers differ.

---

## 4. Rust KMS changes

### Approach: generic internals, enum dispatch at boundary

ZF FROST's `frost-core` defines `trait Ciphersuite`. The session state machine and
storage logic can be made generic over `C: Ciphersuite`:

```rust
// Internal: fully generic
struct SessionInner<C: Ciphersuite> { ... }
impl<C: Ciphersuite> SessionInner<C> {
    fn process_message(...) -> ... { ... }
}

// Boundary: enum dispatch in the gRPC service layer
enum Session {
    Secp256k1(SessionInner<frost_secp256k1::Secp256K1Sha256>),
    Ed25519(SessionInner<frost_ed25519::Ed25519Sha512>),
}
```

This keeps the crypto logic shared and type-safe, with the enum only at the service
boundary where gRPC erases types anyway. The match dispatch in `service.rs` is thin.

### Dependencies

```toml
[dependencies]
frost-core = "2.2"
frost-secp256k1 = "2.2"     # existing
frost-ed25519 = "2.2"       # new
```

---

## 5. Storage

Key material is curve-specific and must never be mixed. Prefix sled trees by curve:

```
keys/secp256k1/{group_id}/{key_id}  →  KeyPackage + PublicKeyPackage (secp256k1)
keys/ed25519/{group_id}/{key_id}    →  KeyPackage + PublicKeyPackage (ed25519)
```

The curve prefix makes accidental cross-curve key loading structurally impossible.
`get_key` and `store_key` take a curve parameter that determines which tree to access.

---

## 6. gRPC schema changes

Add a curve identifier to the proto schema:

```protobuf
enum Curve {
  CURVE_SECP256K1 = 0;
  CURVE_ED25519 = 1;
}
```

**Keygen params** (CBOR): add `curve` field. The KMS uses this to select the
ciphersuite for the session.

**PublicKeyResponse**: add `curve` field so the Go node knows how to interpret the
key bytes (33-byte compressed secp256k1 vs 32-byte Ed25519).

**StartSessionRequest**: curve is already encoded in the CBOR params blob, so no
proto-level field is strictly needed, but including it allows the KMS to validate
early before parsing the full params.

**Signature sizes**: secp256k1 Schnorr produces R (33 bytes) + z (32 bytes).
Ed25519 produces a 64-byte signature (R 32 bytes + s 32 bytes). The existing
`SessionResult` fields (`signature_r`, `signature_z`) already use `bytes`, so
no schema change needed — just different lengths.

---

## 7. Go node changes

### KeyInfo

Add a `Curve` field:

```go
type KeyInfo struct {
    GroupKey []byte
    PartyID  tss.PartyID
    Curve    string  // "secp256k1" or "ed25519"
}
```

### Signature

The current `tss.Signature` uses fixed-size arrays (`R [33]byte`, `Z [32]byte`)
for secp256k1. Ed25519 signatures are 64 bytes with a different structure. Options:

- **Preferred**: use `[]byte` for the combined signature, with curve metadata for
  interpretation. Keeps the type simple and avoids a parallel struct.
- Alternative: separate `Secp256k1Signature` / `Ed25519Signature` types.

### Sign/keygen handlers

Pass the curve from the API request through to KMS session params. The bridge layer
(`bridgeSession`) is already curve-agnostic — it just shuttles opaque byte payloads.

### Chain client

The node needs a Solana RPC client alongside the existing Ethereum client. Group
membership and on-chain state for Ed25519 groups comes from the Solana program
instead of the EVM factory contract.

---

## 8. API surface

### `POST /v1/keygen`

Add optional `curve` field (default: `"secp256k1"` for backwards compatibility):

```json
{
  "group_id": "0x...",
  "threshold": 2,
  "curve": "ed25519"
}
```

### `POST /v1/sign`

No curve field needed — inherited from the stored key. The response format adjusts
based on curve (different signature encoding).

### `GET /v1/keys`

Response includes curve per key:

```json
{
  "keys": [
    { "group_id": "0x...", "key_id": "k1", "curve": "secp256k1", "group_key": "02..." },
    { "group_id": "0x...", "key_id": "k2", "curve": "ed25519", "group_key": "..." }
  ]
}
```

---

## 9. Contract layer

**No changes to EVM contracts.** `SignetFactory` and `SignetGroup` continue to manage
secp256k1 groups exclusively. They do not need awareness of Ed25519 groups.

If we later want on-chain awareness of Ed25519 groups on EVM (e.g., for cross-chain
orchestration), that would be a separate design — but it is not required for Solana
signing to work.

---

## 10. Solana program

A Solana program (`signet-program`) serves the same role as `SignetGroup` on EVM:

- Stores group membership and public keys on-chain
- Verifies FROST-produced Ed25519 signatures using Solana's native
  `Ed25519SigVerify` precompile (essentially free — it's a syscall)
- Manages group lifecycle (creation, member changes, key rotation)

The Solana program is a separate deliverable from the multi-curve KMS work. The KMS
and node can produce valid Ed25519 threshold signatures before the Solana program
exists — the program is needed for on-chain verification and group management.

---

## 11. Future curves

The generic-over-`Ciphersuite` approach in the KMS means adding another curve is:

1. Add the `frost-{curve}` crate dependency
2. Add a variant to the `Session` enum and `Curve` proto enum
3. Add a storage tree prefix
4. Build the target chain integration

Candidates: Ed448, P-256 (WebAuthn/passkey signing), Ristretto255.

---

## Implementation order

1. **KMS generics** — make session/storage generic over `Ciphersuite`, add Ed25519
   variant, test with unit tests
2. **Proto + Go plumbing** — curve field in params/responses, variable signature
   handling in Go node
3. **Devnet validation** — run mixed-curve groups in devnet, verify keygen and
   signing for both curves
4. **Solana program** — on-chain group management and signature verification
5. **Chain client** — Solana RPC integration in the Go node
