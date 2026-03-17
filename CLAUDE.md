# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Signet: threshold signing research using `luxfi/threshold` library (LSS protocol). The project includes smart contracts, a Go node with libp2p networking, an HTTP API, blockchain integration, and a ZK-based authentication layer.

- Main module: `signet` (Go)
- Local threshold library fork: `threshold-local/` (module `github.com/luxfi/threshold`)
- Smart contracts: `contracts/` (Foundry, Solidity 0.8.24)
- ZK circuit: `circuits/jwt_auth/` (Noir + Barretenberg)

## Build and Test Commands

```bash
# Go
go test ./...                    # all tests (node, network)
go test -v -run TestName ./...   # specific test
go build ./...                   # build all
go vet ./...                     # lint

# Solidity
forge test                       # all Foundry tests (55 tests)
forge build                      # compile contracts

# ZK circuit (requires nargo + bb)
cd circuits/jwt_auth
nargo compile --force
nargo execute bench_witness
bb prove -b target/jwt_auth.json -w target/bench_witness.gz -o target/proof --write_vk
bb verify -k target/proof/vk -p target/proof/proof -i target/proof/public_inputs
```

## Claude Code Instructions

### Autonomy & Decision-Making

Proceed without asking for confirmation whenever possible. Bias toward action.
Make reasonable assumptions and state them after the fact rather than stopping to ask upfront.
If you hit an ambiguity on a small detail, pick the most sensible option and move on.
Only pause and check in when a decision is **irreversible** or **high-risk** (see below).

### Always Allowed (No Confirmation Needed)

**Read-only operations — never ask:**
- Reading any file, directory, or config
- Searching and grepping the codebase
- Running linters, type-checkers, or static analysis
- Running tests (read-only test runs)
- Viewing git log, diff, status, blame
- Inspecting environment variables (non-secret)
- Web searches or fetching documentation

**Safe write operations — proceed without asking:**
- Creating or editing source files
- Installing dependencies (`npm install`, `pip install`, etc.)
- Creating new files, directories, or configs
- Running build scripts (`npm run build`, `make`, etc.)
- Executing non-destructive shell commands
- Writing or updating tests
- Reformatting or refactoring code

### Always Require Explicit Permission

**Stop and ask before doing any of the following:**

- `git commit` — never commit without approval
- `git push` — never push to any remote without approval
- Opening or merging pull requests
- Deleting files or directories
- Dropping or truncating databases or data
- Modifying environment variables in production configs
- Any action that affects external services or sends network requests with side effects (emails, webhooks, payments, etc.)
- Changing CI/CD pipelines or deployment configs

### Code Style & Conventions

- Follow existing patterns in the codebase — consistency over personal preference
- Don't introduce new dependencies without mentioning it
- Prefer editing existing files over creating new abstractions unless necessary
- Write tests for any non-trivial logic you add or change
- Leave code at least as clean as you found it

### How to Handle Uncertainty

- **Small ambiguity** (naming, minor structure): pick the best option, note your choice at the end
- **Medium ambiguity** (architecture, approach): state your assumption and proceed, flag it in your summary
- **Large ambiguity** (unclear requirements, missing context): ask one focused question before proceeding

### Task Completion

When finishing a task, always provide a brief summary of:
1. What you did
2. Any assumptions you made
3. Anything that requires a follow-up decision (especially commits, pushes, or destructive actions)

---

## Architecture & Key Dependencies

### Go Dependencies
- `github.com/luxfi/threshold` — threshold crypto (LSS keygen/sign, curve math, party IDs, pool)
- `github.com/ethereum/go-ethereum v1.17.1` — chain client, ABI, crypto
- `github.com/lestrrat-go/jwx/v2` — JWT parsing/verification, JWKS caching (jwk, jwt, jwa)
- `github.com/fxamacker/cbor/v2` — CBOR encoding for coord messages
- `github.com/libp2p/go-libp2p` — P2P networking (streams, GossipSub)
- `go.etcd.io/bbolt` — key shard persistence

### Solidity Dependencies
- OpenZeppelin Contracts Upgradeable v5 (UUPSUpgradeable, BeaconProxy, Initializable)
- `foundry.toml`: `via_ir = true` (required for large initialize signature)

---

## LSS Protocol Design

### Handler Framework Contract
- `initializeRound` guard: `r.MessageContent() != nil && !h.hasAllMessages(r)`
- BroadcastRound-only rounds (MessageContent() == nil) bypass this → finalize immediately after 20ms
- "Return self" from Finalize → `finalizeRound` schedules `tryAdvanceRound` after 10ms

### Round Pattern: "Send once, return self until all arrive"
Used in sign/round1, sign/round2, keygen/round1:
1. Generate/compute values ONCE (idempotent, checked via nil guard)
2. Send broadcast ONCE (guarded by `broadcastSent bool`)
3. Return self if count < N (use sync.Map for thread-safe counting)
4. Return next round with fully-populated map when all N arrive

### CBOR Serialization: curve.Point/Scalar must be []byte
`curve.Point` and `curve.Scalar` are interfaces — CBOR cannot unmarshal into them directly.
Always encode as `[]byte`, then unmarshal in StoreBroadcastMessage.

### Threshold Signing Math
LSS uses additive secret sharing (NOT standard ECDSA):
- Partial sig: `s_i = k_i + r · λ_i · x_i · m`
- Combined: `s = k + r · x · m`
- Verification (Schnorr-style): `s·G = R + r·m·X`
- Done INLINE in `sign/round3.go:verifyThreshold()` — NOT via `ecdsa.Signature.Verify`

---

## Smart Contracts

- `contracts/SignetFactory.sol` — UUPS factory + node registry + UpgradeableBeacon owner
- `contracts/SignetGroup.sol` — BeaconProxy group impl; swap-and-pop O(1) member removal
- Factory reverse mapping: `getNodeGroups(addr)`, `getNodePubkey(addr)`, O(1) swap-and-pop
- Two-step BeaconProxy deploy: deploy proxy with empty data → set `isGroup[group]=true` → call `group.initialize()`
- OAuth issuer management: on-chain trusted issuer lifecycle with time-delayed add/remove

### Key Solidity Lessons
- OZ v5: `UUPSUpgradeable` is stateless — no `__UUPSUpgradeable_init()` call needed
- `vm.createWallet(privKey)` → `Vm.Wallet{publicKeyX, publicKeyY}` for secp256k1 pubkeys in tests
- Public mapping of a struct generates a tuple getter — use internal mapping + explicit getter for interfaces

---

## Node Architecture

### Config (`node/config.go`)
- `DataDir`, `ListenAddr`, `APIAddr`, `AnnounceAddr`, `BootstrapPeers`, `NodeType`
- `EthRPC`, `FactoryAddress` — blockchain integration
- `TestMode` — skip JWT signature/expiry checks, trust initiator attestation for ZK auth
- `VKPath` — path to circuit verification key (bb format, required for production ZK auth)

### HTTP API
- `GET /v1/health`, `GET /v1/info`, `GET /v1/keys[?group_id=0x...]`
- `POST /v1/auth` — register session key (test mode: JWT; production: ZK proof + claims)
- `POST /v1/keygen` — distributed key generation
- `POST /v1/sign` — threshold signing

### Chain Client (`node/chain.go`)
- Polls factory events (`NodeActivatedInGroup/Deactivated`) and group events every 2s
- Loads group membership + issuers from chain at startup
- `reflect.ValueOf(results[0]).FieldByName("Issuer")` pattern for go-ethereum tuple[] unpacking

### Storage (`node/keystore.go`)
- bbolt nested buckets: `keyshards` → `<groupID>` → `<keyID>` → JSON lss.Config

---

## ZK Auth + Session Key Scheme

### Design
- **Auth phase** (once per JWT lifetime): client generates ZK proof of JWT validity bound to ephemeral session key, sends to `POST /v1/auth`
- **Request phase** (per operation): client signs request params with session private key
- JWT signature never leaves the client — nodes only see the ZK proof
- See `docs/DESIGN-ZK-AUTH.md` for full spec, `docs/SECURITY-ANALYSIS.md` for threat model

### Auth Flow
1. Client: OAuth login → JWT → generate session keypair → fetch OIDC JWKS → generate ZK proof → `POST /v1/auth`
2. Node: verify ZK proof (bb verify) + check JWKS modulus against OIDC cache + cache session
3. Client: sign requests with session key → `POST /v1/keygen` or `/v1/sign`
4. Node: verify request signature against cached session pub → build AuthProof → broadcast to participants via coord message
5. Each participant: independently verify ZK proof + request signature + nonce + timestamp

### BB Verify Integration (Phase 1)
- `node/zkverify.go`: `encodePublicInputs` (AuthProof → 568 × 32-byte BN254 field elements), `verifyBBProof` (shells out to `bb verify`), `findBB` (PATH + `~/.bb/bb`)
- `ValidateAuthProof` production path: verify JWKS modulus → encode public inputs → `bb verify`
- `/v1/auth` production body: `{proof, sub, iss, exp, aud, azp, jwks_modulus, session_pub}` (all hex)
- SessionInfo stores proof + modulus bytes so coord messages carry full proof for participant verification
- Phase 2 planned: embed Barretenberg WASM via wazero (see `docs/DESIGN-BARRETENBERG-WASM-GO.md`)

### Public Input Layout (circuit: `circuits/jwt_auth/src/main.nr`)
Each value → 32-byte big-endian BN254 field element:
1. `pubkey_modulus_limbs` — 18 × u128 (RSA-2048 modulus as 120-bit limbs, LE order)
2. `expected_iss` — BoundedVec<u8, 128> (128 storage + 1 len = 129 elements)
3. `expected_sub` — BoundedVec<u8, 128> (129 elements)
4. `expected_exp` — u64 (1 element)
5. `expected_aud` — BoundedVec<u8, 128> (129 elements)
6. `expected_azp` — BoundedVec<u8, 128> (129 elements)
7. `session_pub` — [u8; 33] (33 elements)
Total: 568 elements × 32 bytes = 18,176 bytes

### Key Design Decisions
- JWKS modulus verification is critical: prevents fake RSA key attacks
- Canonical request hash: `SHA256(groupID:keyID:nonce:timestamp_8bytes_BE[:messageHash])`
- Request sig: secp256k1 ECDSA, 64-byte [R||S]
- TestMode: `/v1/auth` validates JWT directly; coord msg carries `TestMode:true`; participants skip ZK proof only if their own testMode is also true
- Nonce: client-generated random hex, 5min retention for replay check
- Timestamp: 30-second freshness window

### Key API Notes
- jwx v2: `jwt.WithVerify(false)` (not `WithInsecureNoSignatureVerification`)
- `IssuerHash(issuer string) [32]byte` = keccak256 via `crypto.Keccak256Hash`
- `crypto.VerifySignature` accepts compressed 33-byte pubkeys directly
- Auth-scoped key_id derived as `sub` or `sub:suffix`; groups without issuers use key_id directly

---

## Pre-existing Library Failures (NOT our bugs)
- `protocols/lss/TestLSSDynamicReshareStress/CompletePartyReplacement` — panic: nil secp256k1Point
- `protocols/unified/adapters` — build fail: `GeneratePreprocessing` undefined
