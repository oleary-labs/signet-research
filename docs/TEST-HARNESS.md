# Signet Test Harness

The test harness is a single Go binary (`cmd/harness`) that drives keygen and sign
operations against a running Signet environment and measures correctness, performance,
and scalability. The same binary and same test scenarios run against a local devnet or
a remote multi-region testnet.

---

## Environments

**Devnet** — three nodes on localhost, Anvil chain, started with `devnet/start.sh`.

**Testnet** — nodes deployed on remote servers in multiple geographic regions. A
`testnet/` directory (parallel to `devnet/`) holds provisioning scripts and a
`testnet/.env` in the same format as `devnet/.env`.

The harness reads an env file to discover everything it needs. The format is the
same as the one written by `devnet/start.sh`:

```
RPC_URL=http://...
FACTORY_ADDRESS=0x...
GROUP_ADDRESS=0x...
NODE1_API=http://localhost:8080
NODE2_API=http://localhost:8081
NODE3_API=http://localhost:8082
NODE1_PEER=16Uiu2H...
NODE2_PEER=16Uiu2H...
NODE3_PEER=16Uiu2H...
NODE1_ETH=0x...
NODE2_ETH=0x...
NODE3_ETH=0x...
```

Testnet env files extend this with optional region annotations used in output:

```
NODE1_REGION=us-east-1
NODE2_REGION=eu-west-1
NODE3_REGION=ap-southeast-1
```

---

## Usage

```bash
# Build
go build -o build/harness ./cmd/harness

# Correctness — pass/fail smoke test
./build/harness -env devnet/.env correctness

# Performance — latency and throughput under load
./build/harness -env devnet/.env perf -concurrency 10 -duration 60s

# Scalability — sweep concurrency levels
./build/harness -env devnet/.env scale -max-concurrency 50 -step 10

# Write JSON results to a file
./build/harness -env testnet/.env perf -concurrency 20 -duration 120s -out results.jsonl
```

All requests go through the node HTTP API — the same interface a real client uses.
The harness does not reach into node internals.

---

## Correctness Scenarios

Run sequentially. Each is pass/fail. Intended as a smoke test on every environment.

| # | Name | What it checks |
|---|------|----------------|
| 1 | keygen-valid-pubkey | Keygen returns a compressed secp256k1 point |
| 2 | sign-verifiable | Sign returns a signature that passes ecrecover verification |
| 3 | sign-nondeterministic | Signing the same message twice produces different signatures |
| 4 | sign-missing-key | Signing with an unknown key_id returns HTTP 404 |
| 5 | concurrent-keygen-isolation | N concurrent keygens produce N distinct public keys |
| 6 | concurrent-sign-isolation | N concurrent signs with the same key all verify |
| 7 | cross-node-consistency | Keygen via node1, sign via node2 — signature verifies |

Signature verification uses the same ecrecover math as `tss/ethereum_test.go`:
compute the FROST challenge `c = H2(R || PK || msg)`, derive ecrecover parameters,
call `crypto.Ecrecover`, and check the recovered address matches the group key.

---

## Performance Scenarios

Each scenario runs workers for a configured duration and collects per-operation
latency. A key pool is pre-generated at startup so sign scenarios measure signing
latency only, not keygen+sign.

| Scenario | Description |
|----------|-------------|
| sequential-baseline | concurrency=1, alternating keygen+sign |
| concurrent-keygen | C workers, each running keygen continuously |
| concurrent-sign | C workers, signing against a pre-generated key pool |
| mixed-load | C/2 keygen workers + C/2 sign workers simultaneously |

### Output

Human-readable summary to stdout:

```
scenario: concurrent-sign  concurrency=10  duration=60s
  operations : 1,243
  success    : 1,241  (99.8%)
  errors     : 2
  throughput : 20.7 ops/sec
  latency p50: 287ms
  latency p95: 412ms
  latency p99: 618ms
```

JSON lines to `-out` file (one record per operation):

```json
{"scenario":"concurrent-sign","op":"sign","ts_ms":1711234567890,"latency_ms":287,"ok":true,"error":""}
```

---

## Scalability Scenarios

Vary a parameter systematically across a range and print a result table.

| Scenario | Parameter swept | Metric observed |
|----------|----------------|-----------------|
| concurrency-sweep | concurrency 1→max in steps | p50/p95 latency, ops/sec |
| key-pool-sweep | pool size 1→N | p50 latency (checks for key-lookup bottleneck) |
| group-size-sweep* | group node count | p50 latency per group size |
| cross-region-latency* | request target node | p50 latency per region |

*Requires testnet with multiple groups or multi-region nodes.

Example concurrency sweep output:

```
scenario: concurrency-sweep
concurrency  ops/sec  p50(ms)  p95(ms)  p99(ms)
          1      2.1      441      512      601
          5      8.9      521      634      790
         10     16.2      587      712      891
         20     24.1      798     1102     1451
         50     28.3     1821     2940     4201
```

---

## Testnet Setup

The testnet mirrors the devnet structure for remote nodes:

```
testnet/
  README.md         — provisioning instructions
  provision.sh      — SSH-based: install signetd binary, write config per node
  start.sh          — deploy contracts, register nodes, write testnet/.env
  stop.sh
  clean.sh
  .env              — generated: API URLs, peer IDs, group address, region tags
```

Assumptions:
- Nodes are pre-provisioned Linux servers with SSH access.
- A shared Ethereum RPC endpoint is accessible from all nodes and the harness runner
  (e.g. a public Sepolia RPC or a shared Anvil instance with a stable address).
- Bootstrap peer config uses public IPs or DNS names, not localhost.
- The harness runner machine can reach all node HTTP APIs over the internet.

Contract deployment and group creation in `testnet/start.sh` follow the same flow
as `devnet/start.sh`, targeting the remote chain and remote nodes.

---

## Source Layout

```
cmd/harness/
  main.go              CLI entry point, flag parsing, subcommand dispatch
  env.go               Env file parsing, node list construction
  client.go            HTTP client: Keygen(), Sign(), Health()
  verify.go            FROST signature verification (ecrecover)
  scenarios/
    correctness.go     7 correctness tests
    perf.go            Sequential baseline, concurrent keygen/sign, mixed load
    scale.go           Concurrency sweep, key-pool sweep, group-size sweep
  metrics/
    collector.go       Per-operation timing and error tracking
    report.go          Stdout summary table + JSON lines writer
```

---

## What Is Out of Scope (for now)

- Automated testnet provisioning (Terraform/Ansible) — manual SSH scripts are sufficient.
- Load generation from multiple geographic origins — all requests come from wherever the harness runs.
- Fault injection (killing nodes mid-protocol, network partitions).
- Continuous / CI integration for perf and scale scenarios. Correctness scenarios could
  run in CI against devnet; perf and scale are run manually.
