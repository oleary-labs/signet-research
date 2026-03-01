# LSS Protocol Analysis

Analysis of the LSS protocol's security model, trust assumptions, and suitability for signet.

---

## Protocol Overview

LSS (Linear Secret Sharing MPC ECDSA) is a threshold signing protocol based on linear secret sharing with a semi-honest adversary model. It performs distributed key generation and signing without any trusted dealer.

| Property | Value |
|----------|-------|
| Adversary model | Semi-honest (honest-but-curious) |
| Rounds (keygen) | 3 |
| Rounds (signing) | 3 |
| Signing time (3-party) | ~8ms |
| Signing time (5-party) | ~15ms |
| Dynamic resharing | Yes — without key reconstruction |
| Identifiable abort | No |

---

## Signing Protocol Message Flow

All LSS signing messages are **broadcast to all participants** — there are no point-to-point messages.

| Round | Message | Content | Visible to |
|-------|---------|---------|-----------|
| 1 | `broadcast1` | Nonce commitment `K_i = g^k_i` (public point) | All signers |
| 2 | `broadcast2` | Partial signature `s_i = k_i + r·λ_i·x_i·m` (scalar) | All signers |
| 3 | — | Local combination: `s = Σs_i`, then `sig.Verify()` | Self only |

The partial signature `s_i` hides the secret share `x_i` behind the ephemeral nonce `k_i`. Without knowing `k_i`, an observer cannot extract `x_i` from `s_i`.

---

## Coordinator Trust Model

The "Signature Coordinator" is an application-layer role — the node that received the signing request, initiated the session, and drives round progression. It is **not** a distinct cryptographic entity.

**What a coordinator can do:**
- Drop messages (liveness attack — can cause signing to abort)
- See all partial signatures (same as every other signer, since they're broadcast)
- Initiate or decline to initiate signing sessions

**What a coordinator cannot do:**
- Extract secret key shares (requires knowing other parties' nonces `k_j`)
- Forge a valid signature without t-of-n cooperation
- Attack past sessions (nonces are fresh per session)

**Trust requirement: liveness only, not secrecy.**

Any node that holds a key share can act as coordinator. The coordinator has no cryptographic advantage over other signing parties — all participants see the same broadcast messages. If a coordinator refuses to route messages, a different node can coordinate the same signing session.

---

## Compromised Node Consequences

Given highly trustworthy nodes (semi-honest model), a single compromised node is constrained to:

| Scenario | Outcome |
|----------|---------|
| Node holds `x_i` (1-of-t shares) | Cannot reconstruct key or forge signatures — needs t shares |
| Node sends bad partial sig `s_i` | Final `sig.Verify()` fails — protocol aborts, no signature produced |
| Node denies participation | Signing fails for any set requiring that node; exclude it and use another t-of-n subset |
| t nodes simultaneously compromised | Private key exposed — unavoidable for any threshold scheme |

**Identifying a misbehaving node:** If a bad `s_i` causes abort, the culprit can be identified post-hoc by verifying each `s_i` against the known public share `X_i`:

```
s_i · G = K_i + r · λ_i · X_i · m · G
```

This check is not performed automatically in the current implementation but can be added to round 3.

The threshold t is the security parameter. Fewer than t simultaneous compromises cannot expose the private key.

---

## Dynamic Resharing

LSS's primary design advantage over CMP is live member rotation without key reconstruction.

```go
func Reshare(c *config.Config, newParticipants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc
```

Passing a `newParticipants` list that excludes a removed node initiates resharing. After completion:

1. **Old shares are cryptographically invalidated** — the new generation uses a completely re-derived secret sharing. The removed node's old `x_i` cannot be used with new-generation configs.
2. **The public key (Ethereum address) is preserved** — no change to the on-chain identity.
3. **The private key is never reconstructed** — resharing distributes new polynomial shares directly between old and new parties via Shamir secret sharing through JVSS.
4. **Generation tracking** (`config.Generation`) prevents mixing old and new shares.

The `RollbackManager` provides fault tolerance: if resharing fails midway, the previous generation's config can be restored.

---

## Semi-Honest Sufficiency for Signet

Semi-honest security is appropriate for signet given the following conditions that apply to this deployment:

- Nodes are operated by a single trusted infrastructure provider
- Compromise of individual nodes is assumed unlikely (high-trust nodes)
- The primary availability concern is node failure, not active adversarial behavior

**Semi-honest is sufficient because:**
- A compromised node cannot extract the key without t-of-1 cooperation from others
- A misbehaving node causes detectable abort, not silent forgery
- The coordinator role requires only liveness trust — any node can coordinate
- Dynamic resharing provides the operational tool to remove a suspected-compromised node

**If the threat model changes** (independently-operated nodes, multi-org deployments), CMP provides malicious-adversary security with identifiable abort at the cost of ~3.5–5s per signing operation.

---

## Comparison: LSS vs CMP for Signet

| Property | LSS | CMP |
|----------|-----|-----|
| Signing latency | ~8–15ms | ~3.5–5s (or ~5ms online with presign) |
| Security model | Semi-honest | Malicious |
| Identifiable abort | No (detectable post-hoc) | Yes (cryptographic) |
| Dynamic resharing | Yes, built-in | No (requires new keygen) |
| Node removal | Via reshare — old shares invalidated | Full new keygen required |
| Coordinator trust | Liveness only | Liveness only |
| Suitable for signet | Yes (single-operator, high-trust) | Yes (multi-operator, lower trust) |
