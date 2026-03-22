# FROST Integration Testing

This document covers the cross-language integration test infrastructure for verifying
that Go FROST signing output is compatible with the on-chain `FROSTVerifier` Solidity
contract, and a data race found and fixed in `bytemare/frost` during that work.

---

## Problem

The Solidity `FROSTVerifier` tests in `contracts/test/FROSTVerifier.t.sol` originally
used hardcoded test vectors — constants manually copied from a previous run of
`cmd/testvector`. This verified the contract logic but not the live Go→Solidity pipeline:
if signing math changed, the Solidity tests would still pass against stale constants.

---

## What Was Built

### 1. Go-side ecrecover integration test (`tss/ethereum_test.go`)

`TestSigEthereumEcrecover` runs a full 2-of-3 FROST keygen+sign on every `go test`
invocation, then verifies the resulting signature using the same math the Solidity
contract uses — without requiring forge to be installed.

The verification mirrors `FROSTVerifier.verify()` step by step in Go:

1. Compute the FROST challenge `c = H2(R_compressed || groupKey || msgHash)` via
   `expand_message_xmd` (RFC 9380) with SHA-256 and DST `"FROST-secp256k1-SHA256-v1chal"`.
2. Derive ecrecover parameters:
   - `c_inv = c^(-1) mod N`
   - `s_ec  = -rx · c_inv mod N`
   - `hash_ec = -rx · z · c_inv mod N`
3. Call `crypto.Ecrecover(hash_ec, [rx || s_ec || v])` and check the recovered address
   matches `crypto.PubkeyToAddress(groupKey)`.

This test catches any divergence between Go signing output and Solidity verification
logic on every CI run.

### 2. Automated vector generation (`cmd/testvector`)

`cmd/testvector` was updated to write a JSON fixture alongside its stdout output:

```
contracts/test/testdata/frost_vector.json
```

Fields: `groupPubKey`, `msgHash`, `signer`, `sigRx`, `sigZ`, `sigV`.

Regenerate when needed:
```bash
go run ./cmd/testvector/
```

### 3. Solidity integration test (`FROSTIntegrationTest` in `FROSTVerifier.t.sol`)

Reads `test/testdata/frost_vector.json` via `vm.readFile` + `vm.parseJson*` and verifies
the Go-generated signature via `FROSTVerifier.verify()`. `foundry.toml` grants read
access to that path via `fs_permissions`.

This closes the loop: Go signs → JSON written → Solidity reads and verifies on-chain.

**Workflow for a full cross-language check:**
```bash
go run ./cmd/testvector/   # regenerate fresh signature
cd contracts && forge test  # verify it on-chain
```

---

## Data Race in `bytemare/frost`

### Root cause

`github.com/bytemare/frost/internal/hashing.go` declares a package-level array:

```go
var ciphersuites = [ecc.Secp256k1Sha256 + 1]ciphersuite{
    ...
    { // Secp256k1
        hash: hash.SHA256.New(),   // single *hash.Fixed, created once at package init
        ...
    },
}
```

`H4` and `H5` copy the `ciphersuite` struct by value, but `hash` is an interface holding
a pointer — the copy shares the same underlying `*hash.Fixed` object. That object wraps
a `*sha256.Digest` with mutable state (`nx`, block buffer, running hash values).

When two goroutines call `signer.Sign()` or `AggregateSignatures()` concurrently, both
call `bindingFactors()` → `H4`/`H5` → `cs.hash.Hash()` → `Reset()`/`Write()`/`Sum()`
on the **same SHA256 object simultaneously**. Go 1.24's FIPS140 SHA256 implementation
added an assertion (`d.nx != 0`) that turns this latent race into a panic at runtime,
which is how it was discovered.

The race detector confirms it:
```
DATA RACE: Write at sha256.(*Digest).Reset() by goroutine A
           Write at sha256.(*Digest).Write() by goroutine B
```

### Fix (`tss/sign.go`)

A package-level mutex `frostMu` serializes all calls into the affected frost functions:

```go
// frostMu serializes all calls into bytemare/frost that touch the shared Ciphersuite
// hasher. frost.Secp256k1 stores a hash.Fixed that is not goroutine-safe; Sign,
// AggregateSignatures, and VerifySignature all use it.
var frostMu sync.Mutex
```

Applied around `signer.Sign()` (round 1) and `frostCfg.AggregateSignatures()` (round 2).

### Performance impact

Negligible. The mutex is held only during pure-CPU hash computation (~50–200µs).
The dominant cost of a signing session is network round-trips between nodes
(10–200ms per round, 2 rounds). Contention only occurs when two sessions' `Finalize()`
calls land simultaneously — rare in practice due to network jitter, and even when it
happens the wait is invisible against the network time.

A load-test scenario with hundreds of concurrent in-process sessions would see
serialized computation, but the total serialized work (N × ~150µs) remains small
relative to network-bound session time.

### Proper upstream fix

The correct fix in `bytemare/frost` is to use per-call hasher allocation (e.g.,
`hash.SHA256.New()` inside `H4`/`H5`) or a `sync.Pool`. The version in use is
`v0.0.0-20241019112700-8c6db5b04145` (Oct 2024). If upgrading, check whether the
upstream has addressed this before removing `frostMu`.

---

## Files Changed

| File | Change |
|------|--------|
| `tss/ethereum_test.go` | New: Go ecrecover integration test |
| `tss/sign.go` | Added `frostMu`; protect `Sign` and `AggregateSignatures` |
| `cmd/testvector/main.go` | Write `contracts/test/testdata/frost_vector.json` |
| `contracts/test/FROSTVerifier.t.sol` | Added `FROSTIntegrationTest` contract |
| `contracts/foundry.toml` | Added `fs_permissions` for `test/testdata/` |
| `contracts/test/testdata/frost_vector.json` | Generated fixture (gitignore or commit) |
