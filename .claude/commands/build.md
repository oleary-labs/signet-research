# /build Command

Build a feature or make a change using the architect → engineer → reviewer workflow.

## Usage
`/build "feature or change description"`

## Workflow (Sequential)

### Stage 1: Design (architect)
Load `.claude-library/agents/core/architect.md` and `.claude-library/contexts/project.md`.
- Design the approach: protocol changes, data structures, API shapes
- Identify which files need to change (`network/`, test files, etc.)
- Output: brief design spec (inline, not a new file unless essential)

### Stage 2: Implement (engineer)
Load `.claude-library/agents/core/engineer.md`.
- Implement the design in Go
- Follow existing patterns in `network/` package
- Write or update tests alongside implementation

### Stage 3: Review (reviewer)
Load `.claude-library/agents/core/reviewer.md`.
- Check correctness, error handling, and Go idioms
- Verify `go test ./...` would pass
- Flag any security or concurrency issues

## Success Criteria
- Code compiles (`go build ./...`)
- Tests pass (`go test ./...`)
- Follows existing conventions in the codebase
