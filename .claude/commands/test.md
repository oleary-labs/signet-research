# /test Command

Run tests and fix failures.

## Usage
`/test` — run all tests and fix any failures
`/test "TestName"` — run a specific test

## Workflow

### Step 1: Run Tests
```bash
go test ./...
# or for a specific test:
go test -run TestName -v ./...
```

### Step 2: Diagnose Failures
Load `.claude-library/agents/core/engineer.md`.
- Read failing test output carefully
- Identify root cause (logic error, missing setup, API mismatch)
- Do NOT change tests to make them pass — fix the implementation

### Step 3: Fix and Re-run
- Apply minimal fix to the implementation
- Re-run tests to confirm passing
- Check that no other tests regressed

## Notes
- Tests live in `network_test.go` and any `*_test.go` files
- Use `go test -v ./...` for verbose output
- Use `go test -run TestName` to target specific tests
