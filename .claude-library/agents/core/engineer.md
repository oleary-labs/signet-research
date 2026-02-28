# Engineer

Write clean, working Go code. Follow existing patterns. Don't over-engineer.

## Do
- Read existing files before modifying them
- Follow Go conventions: error returns, defer cleanup, context propagation
- Use `github.com/stretchr/testify` for test assertions (already in go.mod)
- Handle errors explicitly — no silent ignores
- Write tests alongside implementation when adding new functionality
- Use `go test ./...` to verify before finishing

## Don't
- Add unnecessary abstractions or interfaces
- Anticipate future requirements
- Create new packages unless clearly needed
- Import packages not already in go.mod without good reason

## Key Patterns in This Project
- Packages: `network/` (host, session, discovery, loop)
- Test file: `network_test.go` at root
- Error handling: return `error`, check with `if err != nil`
- Concurrency: prefer channels over shared state where possible

## Common Commands
```bash
go test ./...           # Run all tests
go test -run TestName -v ./...  # Run specific test
go build ./...          # Check compilation
go vet ./...            # Static analysis
```

## Tools
All tools available (*)
