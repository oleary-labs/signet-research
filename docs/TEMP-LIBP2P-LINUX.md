# libp2p Resource Exhaustion on Linux Servers

## Context

Investigating an app using libp2p that, under heavy load, appears to create fresh connections per interaction rather than reusing them. The concern: are there known libp2p issues that could cause this pattern to eventually exhaust server resources?

**Short answer: yes.** "Fresh connection per interaction" is one of the canonical triggers for libp2p resource exhaustion on Linux. There are several distinct failure modes that look similar but have different root causes and fixes.

## Failure Modes to Be Aware Of

### 1. Resource Manager limits hit

Go-libp2p ships with a built-in Network Resource Manager that caps connections, streams, file descriptors, and memory at three scopes: `system`, `transient`, and per-peer. Defaults are conservative.

- Typical log signature: `system: cannot reserve inbound connection: resource limit exceeded`
- Default per-IP connection cap is 8 — breaks badly when peers share a NAT
- Operators commonly bump system-scope limits significantly (e.g., 2048 conns, 4096 streams) just to stop the error flood

### 2. Connection accumulation / slow cleanup

Connections pile up faster than they're cleaned up. Documented in older rust-libp2p (Substrate hit 2000+ open connections after a few hours, with each preallocating buffers). This is the near-universal symptom of fresh-connection-per-interaction workloads.

### 3. Goroutine leaks (DHT and identify)

The most insidious mode. Vocdoni traced production crashes to `go-libp2p-kad-dht`'s `ProviderManager` handling `GetProviders` requests serially — under load, requests pile up, each pending request holds a goroutine. They saw gateways spike to ~200K goroutines before OOM. There have also been historical fixes for goroutine leaks on quick connect/disconnect cycles and in the identify protocol when stream opening fails.

### 4. Memory leaks tied to QUIC / old connections

A 2024 go-libp2p issue documented a regression where old connections stayed referenced on the heap and weren't garbage collected. Even on current versions, regressions happen — pin and test.

### 5. DoS-class CVEs in older versions

A coordinated disclosure across all three implementations covered targeted resource exhaustion attacks against connection, stream, peer, and memory management:

- js-libp2p: fixed in v0.38.0 (GHSA-f44q-634c-jvwv)
- go-libp2p: GHSA-j7qp-mfxf-8xjw
- rust-libp2p: GHSA-jvgw-gccv-q5p8

If your version predates these, upgrading is non-optional.

## Diagnostic Checklist

Before changing code, get visibility on which resource is actually leaking:

- `lsof -p <pid> | wc -l` over time — climbing without bound = FD leak
- `cat /proc/<pid>/status | grep Threads` and goroutine count via pprof — monotonic climb is the giveaway
- `ss -tan | awk '{print $1}' | sort | uniq -c` — lots of `CLOSE_WAIT` or `TIME_WAIT` means one side isn't cleaning up
- RSS over a multi-day window — sawtooth = healthy GC; monotonic growth = leak
- On go-libp2p, the resource manager exposes per-scope stats (analogous to `ipfs swarm stats system` / `transient`) — these tell you exactly which scope is saturating

## Likely Fixes (in order)

1. **Address the connection-per-interaction pattern first.** Libp2p is designed around long-lived connections with multiplexed streams. The intended pattern is: open one connection per peer, then open many cheap streams over it. Switching to stream-per-interaction over a persistent connection often makes the resource pressure disappear entirely.
2. **Upgrade to a current libp2p release.** Particularly important if predating the 2022–2023 DoS advisories.
3. **Raise resource manager limits deliberately** — based on observed saturation, not blindly.
4. **Raise `ulimit -n`** so the process can actually use the configured limits.
5. **Configure a connection manager** with low/high watermarks so idle connections get pruned.

## Open Questions

To get more specific guidance, the following would help narrow it down:

- Which language binding: go-libp2p, rust-libp2p, or js-libp2p?
- Approximate version?
- Which transports are enabled (TCP, QUIC, WebSockets)?
- Is the DHT enabled, and is the node acting as a server or client in the DHT?