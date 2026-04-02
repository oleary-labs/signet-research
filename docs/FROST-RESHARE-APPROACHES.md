# FROST Reshare Approaches: Lagrange-Weighting vs Dynamic-FROST

Analysis of resharing techniques in the context of signet's planned committee-change
reshare (`docs/DESIGN-RESHARE.md`) and ZcashFoundation/frost's same-committee refresh.

---

## 1. Lagrange-Weighting on Top of Feldman VSS

### Applicability to ZF FROST

The Lagrange-weighting technique (Herzberg et al. 1995) operates on the raw scalar share
`s_i` — the output of Feldman VSS — not on anything DKG-specific. ZF FROST's ZK proofs
of knowledge are part of the initial key generation ceremony only; they have no effect on
the structure of the resulting shares.

Both bytemare/dkg and ZF FROST's DKG produce shares of the same form:

```
a = Σᵢ λᵢ · sᵢ    (Lagrange reconstruction identity)
```

The reshare only requires: extract `s_i`, compute `wᵢ = λᵢ · sᵢ`, build a new
degree-(t_new-1) polynomial with constant term `wᵢ`, distribute VSS evaluations to new
parties. This is independent of how `s_i` was originally generated.

Implementing Lagrange-weighting reshare on top of ZF FROST key material would be
identical in structure to signet's design. The only friction is at the API level: ZF
FROST's `KeyPackage` would need to be unwrapped to extract the raw scalar, since ZF FROST
exposes no committee-change reshare method.

### ZF FROST's Refresh is the Degenerate Case

ZF FROST's same-committee refresh and signet's committee-change reshare are both
applications of the same underlying technique. The distinction is entirely in what the
constant terms `fᵢ(0)` sum to:

| | ZF FROST refresh | Signet reshare |
|---|---|---|
| Polynomial constant term | `fᵢ(0) = 0` (zero-sum) | `fᵢ(0) = λᵢ · sᵢ` (Lagrange-weighted) |
| Net effect on secret | `Σ fᵢ(0) = 0` → secret unchanged | `Σ fᵢ(0) = Σ λᵢsᵢ = a` → secret redistributed |
| Committee | Same in, same out | Old in, new out |
| Party identifiers | Unchanged | New party map assigned |

ZF FROST's approach is the special case where the new shares encode the same secret in
the same positions. Signet's is the general case where the set of positions changes.

---

## 2. How Dynamic-FROST Differs

Dynamic-FROST (eprint 2024/896) is a fundamentally different protocol, not a variant of
Lagrange-weighting. It combines FROST with CHURP (CHUrn-Robust Proactive secret sharing).

### Adversary model

Lagrange-weighting assumes honest majority *at the time of reshare*: if `t` or more old
parties are corrupted during the reshare round, the secret leaks. This is the classical
proactive security limitation.

Dynamic-FROST is designed for an adaptive adversary that can corrupt parties dynamically
*across* the reshare. The old committee can be entirely replaced even if a quorum of old
parties is corrupt at handoff time — the new committee gains a fresh sharing of the secret
without the old committee being able to reconstruct it afterward.

### Bivariate polynomials

Dynamic-FROST uses CHURP as its handoff mechanism. CHURP replaces the univariate
polynomials of Feldman VSS with bivariate polynomials `f(x, y)`. Each old party holds an
evaluation in one variable; new parties receive evaluations in the other. A single old
party's contribution is insufficient to reconstruct anything useful without cooperation
from a quorum of new parties — this is what enables the stronger adversary model.

### Communication and complexity

Lagrange-weighting is `O(n_old · n_new)` unicast messages per reshare session (each old
party sends one evaluation to each new party). CHURP's bivariate sharing step is `O(n²)`,
plus additional rounds for commitment verification and ZK proofs at every reshare (not
just initial DKG).

---

## 3. Comparison

| | Lagrange-weighting (signet) | ZF FROST refresh | Dynamic-FROST |
|---|---|---|---|
| Committee change | Yes | No (same committee only) | Yes |
| Threshold change | Yes | Blocked (post v2.2.0 fix) | Yes |
| Security model | Honest majority during reshare | Honest majority during refresh | Adaptive adversary across reshare |
| Protocol complexity | Low (3 rounds, univariate VSS) | Low (3 rounds, univariate VSS) | High (bivariate, extra proof rounds) |
| Communication | O(n_old · n_new) unicast | O(n) unicast | O(n²) |
| Old shares invalidated | No — operational/on-chain only | No — social only | Yes — by construction |
| ZK proofs | No (same gap as bytemare/dkg) | No | Yes, throughout handoff |
| Implementation status | Design spec (`DESIGN-RESHARE.md`) | Production (ZF FROST v3) | Research prototype only |

---

## 4. Why Lagrange-Weighting Is the Right Choice for Signet

Dynamic-FROST's stronger cryptographic invalidation of old shares is not necessary for
signet's threat model:

- **Permissioned groups**: node membership is gated by on-chain registry; joining requires
  an on-chain transaction observable by all participants.
- **Short reshare window**: reshare is explicit and operator-triggered, not continuous.
  The window during which an adaptive adversary could corrupt `t` old parties mid-reshare
  is narrow and observable.
- **Generation counter**: the on-chain `Generation` field and chain client's rejection of
  coord messages referencing superseded generations provides the operational equivalent of
  cryptographic share invalidation. Old shares cannot be used in practice even though they
  remain valid mathematically.
- **Implementation cost**: Dynamic-FROST's bivariate polynomial protocol is significantly
  more complex, has O(n²) communication, and exists only as a research prototype. The
  marginal security gain does not justify the implementation risk.

Lagrange-weighting is well-studied, has clean published correctness proofs, and maps
directly onto signet's existing `tss.Run` round framework.
