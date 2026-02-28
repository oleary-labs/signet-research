# Project Context: signet

## Overview
Research project exploring OneKey threshold signing. Uses the `luxfi/threshold` library for MPC key generation and signing, with `libp2p` for P2P transport.

## Tech Stack
- **Language**: Go 1.24.6
- **Threshold crypto**: `github.com/luxfi/threshold` (CMP protocol, Secp256k1)
- **P2P networking**: `github.com/libp2p/go-libp2p` + Kademlia DHT + PubSub
- **Testing**: `github.com/stretchr/testify`

## Project Structure
```
signet/
├── network/
│   ├── host.go        # libp2p host setup
│   ├── session.go     # Party session management
│   ├── discovery.go   # Kademlia DHT peer discovery
│   └── loop.go        # Message routing loop
├── network_test.go    # Integration tests
├── docs/
│   ├── dkm-spec-initial.md       # DKM protocol spec
│   └── dkm-luxfi-reference.md    # luxfi/threshold reference
├── go.mod
└── CLAUDE.md
```

## Key luxfi/threshold APIs
- `pkg/party` — Party ID management
- `pkg/pool` — Worker pool for parallel MPC rounds
- `protocols/cmp` — CMP keygen + signing protocol
- `protocols/unified/adapters` — Chain adapters (Ethereum, etc.)

## Development Commands
```bash
go test ./...           # Run all tests
go test -run TestBasic  # Run specific test
go test -v ./...        # Verbose output
go build ./...          # Compile check
go vet ./...            # Static analysis
```

## Conventions
- Error handling: explicit `if err != nil { return err }`
- Context: pass `context.Context` as first arg for cancellation
- Logging: use `go.uber.org/zap` (available via luxfi/log)
- No global state — pass dependencies explicitly
