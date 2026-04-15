# Key Derivation: Analysis of Root-Key + Subkey Architectures

## Status: Research / Decision Record

## Context

Resharing keys when group membership changes is O(keys) per group — every key must be independently migrated to the new committee. At scale (thousands of keys per group), this is expensive and creates a long transient window where further topology changes are blocked. NEAR's Chain Signatures project avoids this entirely through a root-key + derivation architecture. This document analyzes whether a similar approach could work for Signet, and concludes that it cannot in its simple form due to Signet's key export requirement.

## NEAR Chain Signatures: Architecture Overview

### Multi-Domain Root Keys

NEAR's MPC network holds a small number of **root keys**, organized by "domain" — a `(DomainId, Curve, Purpose)` triple. Their current configuration has 4 domains:

| Domain | Curve | Purpose |
|---|---|---|
| 0 | secp256k1 | Sign |
| 1 | ed25519 | Sign |
| 2 | BLS12-381 | CKD (Confidential Key Derivation) |
| 3 | secp256k1 | ForeignTx |

Each domain has one root key generated via DKG. Committee change = reshare 4 keys. Done.

### Additive Key Derivation

User-specific keys are derived additively from the root key at sign time:

```
tweak = SHA3-256("near-mpc-recovery v0.1.0 epsilon derivation:" + account_id + "," + path)
derived_pubkey = root_pubkey + tweak * G
```

At the threshold level, each node independently computes `derived_share_i = root_share_i + tweak`. This works because additive tweaking is homomorphic over Shamir shares: if shares reconstruct to `sk`, then `(share_i + tweak)` reconstruct to `sk + tweak`. The root key shares are never combined.

The derivation path is a free-form string; `account_id` (the NEAR account calling the contract) provides implicit namespacing.

### Signing Protocols

NEAR uses different protocols per curve:
- **secp256k1 (ECDSA):** Cait-Sith (OT-based, derived from [cronokirby/cait-sith](https://github.com/cronokirby/cait-sith)). Offline preprocessing generates presignatures via oblivious transfer; online signing is 1 round. Requires `n >= t` participants.
- **secp256k1 (ECDSA, robust fallback):** DJNPO20 ([eprint 2020/501](https://eprint.iacr.org/2020/501)). 3-round presignature protocol, no OT. Requires `n >= 2t+1`. Used when Cait-Sith fails (malicious participant detected).
- **ed25519:** Standard FROST (Komlo-Goldberg) via [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost).

NEAR needs ECDSA because they produce signatures for Bitcoin/Ethereum transactions. Signet uses FROST on secp256k1 (Schnorr signatures), which is simpler — no preprocessing phase, 2-round signing.

### Production Performance

- 3 nodes, threshold 2-of-3 (plans to expand to ~10+)
- End-to-end latency: ~10-15s (includes NEAR block finality), targeting sub-5s in v2.0
- Presignature generation (Cait-Sith): ~200-500ms each, batched continuously
- Throughput target: ~100 sigs/sec with sufficient presignature inventory

### Committee and Governance

The MPC committee is **separate from the NEAR validator set** — a curated set of ~8 nodes operated by known entities (Pagoda, ecosystem partners), not tied to proof-of-stake rotation. Membership changes are governed by multisig-style voting among current committee members via the MPC contract (`v2.multichain.near` on mainnet). In practice, there have been fewer than 2-3 actual committee changes on mainnet through early 2025, primarily adding nodes or replacing underperformers. Committee change is a rare, manually coordinated operation, not routine rotation.

This is critical context for why O(1) reshare via derivation is sufficient for NEAR: they rarely reshare at all.

### Product Model

Chain Signatures is exposed as a **NEAR smart contract call**: `sign(payload, path, key_version)`. Applications interact via NEAR transactions, paying gas + a per-signature fee (~1 NEAR, later reduced). The derivation `path` parameter lets each NEAR account deterministically derive chain-specific keys from the MPC root key.

**Supported chains:** Any chain using ECDSA/secp256k1 — Bitcoin, Ethereum, all EVM chains, Cosmos, XRP Ledger, etc.

**Primary consumers:**
- NEAR Wallet — "your NEAR account is a multi-chain account" (the main pitch)
- Sweat Wallet — multi-chain support via chain signatures
- Bridges and DeFi protocols (Ref Finance, others) — cross-chain swaps

**SDK:** `chainsig-sdk` (JS/TS) wraps contract calls and handles constructing chain-specific transactions.

**Key limitation:** ~15-30s signature latency in production due to MPC rounds + NEAR block finality, constraining real-time use cases.

### Key Repo

[github.com/near/mpc](https://github.com/near/mpc) (Rust). Crypto in `crates/threshold-signatures/`. Design docs in `docs/`.

## Applicability to Signet

### Why the NEAR Model Doesn't Transfer Directly

NEAR's architecture makes perfect sense for their operating context, but differs from Signet on every relevant axis:

| | NEAR | Signet |
|---|---|---|
| Committee control | Protocol-governed, ~8 curated nodes | Application-controlled, dynamic |
| Membership changes | Rare (2-3 ever), manually coordinated | Expected to be frequent, automated |
| Key export | Not supported | Required (user sovereignty) |
| Trust model | MPC network is permanent custodian | Application policy + user sovereignty |
| Interaction | NEAR contract call | Direct HTTP API |

The derivation scheme works for NEAR because they have a small, stable committee that rarely changes, no export requirement, and the MPC service is protocol infrastructure — not application-owned groups with dynamic membership.

### Why Derivation is Attractive

Signet's reshare problem scales linearly with key count. A group with 10,000 keys requires 10,000 independent reshare protocol executions on committee change. With root-key derivation, this collapses to a single reshare regardless of key count. "Key creation" becomes free — just register a derivation path, no DKG needed.

### FROST Compatibility

Additive derivation works with FROST. Given `share_i' = share_i + tweak`, each partial signature becomes `s_i = k_i + challenge * lambda_i * (share_i + tweak)`. Aggregated: `s = k + challenge * (sk + tweak * sum(lambda_i))`. Since Lagrange coefficients sum to 1: `s = k + challenge * (sk + tweak)` — a valid Schnorr signature under the derived key. The math holds.

## The Export Problem

Signet's core value proposition is protecting the application's interests (policy-gated signing) **while also** protecting the end user's sovereignty. Key export — allowing the user to extract their full private key — is essential to this. Without it, Signet is a custodial lock-in, worse than competitors like Privy that already support export.

### Non-Hardened Derivation (NEAR's approach) Breaks on Export

With `tweak = Hash(public_info, path)`, the tweak is publicly computable. If a user exports their derived private key:

```
master_private = derived_private - tweak
```

One export compromises the master key and every other derived key in the group. This is fatal.

### Random Nonce (Plaintext on Nodes) Breaks on Single Malicious Node

An alternative: replace the deterministic tweak with a random nonce stored on each node.

```
derived_key = master_key + nonce
```

Export is safe if the nonce is secret — the user gets `derived_private` but can't recover `master_private` without knowing `nonce` (discrete log protects `nonce * G`).

**However:** if the nonce is stored as plaintext on every node, a single malicious node can leak it. Then: `master_private = exported_derived_private - leaked_nonce`. This weakens the trust assumption from t-of-n to n-of-n for export safety — any single dishonest node compromises the master.

More precisely: the attack requires the derivation to be guessable or leakable. If the tweak is deterministic from public info (NEAR's model), it's trivially known. If it's a random nonce stored on nodes, it requires one malicious node to leak it. In either case, the combination of an exported child key plus knowledge of the tweak yields the master key.

### Threshold-Shared Nonce Recovers Trust but Loses the Reshare Benefit

To maintain t-of-n trust: threshold-share the nonce. Each node holds `nonce_share_i`, and `derived_share_i = master_share_i + nonce_share_i`. Export requires threshold reconstruction of the derived key, and no single node can leak the nonce.

But now each wallet has threshold-shared secret material (the nonce) that must be reshared when the committee changes. This is exactly the per-key reshare problem we were trying to avoid. The win disappears.

### Blinding via a Second Threshold-Shared Master

A more sophisticated approach: derive the nonce from a second threshold-shared secret using a PRF (pseudorandom function, e.g., HMAC-SHA256):

```
nonce = PRF(blinding_master, wallet_id)
derived_key = signing_master + nonce
```

Reshare cost = 2 keys (signing master + blinding master), regardless of wallet count. Export is safe because the nonce requires threshold reconstruction of the blinding master to compute.

**The problem:** evaluating `PRF(threshold_shared_key, wallet_id)` without reconstructing the blinding key requires a **threshold PRF protocol** — an MPC sub-protocol that would need to run on every signing operation (the nonce is needed to compute the derived share). This adds at least one round of communication and significant latency to every signature, not just to key creation or export. The signing hot path becomes substantially more expensive.

## Decision

| Approach | Reshare cost | Export safe? | Trust model | Signing overhead |
|---|---|---|---|---|
| NEAR (deterministic tweak) | O(1) | No | t-of-n | None |
| Random nonce, plaintext | O(1) | No (1 malicious node) | Weakened | None |
| Random nonce, threshold-shared | O(keys) | Yes | t-of-n | None |
| Threshold PRF blinding | O(1) | Yes | t-of-n | +1 round per sign |
| Independent DKG (current Signet) | O(keys) | Yes | t-of-n | None |

**Key export under t-of-n trust assumptions requires per-key secret material.** There is no known scheme that simultaneously achieves O(1) reshare, safe export, t-of-n trust, and zero signing overhead. The threshold PRF approach comes closest but adds latency to every signature — the one operation that must be fast.

**Signet will continue with independent per-key material.** The reshare hardening work (see `DESIGN-RESHARE-HARDENING.md`) focuses on making O(keys) reshare reliable, idempotent, and fast at scale rather than trying to reduce it to O(1).

## Future Considerations

- If a class of keys emerges that provably never needs export (e.g., application-owned operational keys), those could use non-hardened derivation for O(1) reshare within that class.
- Threshold PRF research is active. If an efficient construction emerges (sub-millisecond, no extra rounds), the blinding approach becomes viable.
- The NEAR architecture is worth revisiting if Signet's trust model ever evolves to allow a "no export" tier alongside exportable keys.
