# OneKey Research Agent Launcher

Minimal agent launcher for the onekey-research project — threshold signing + libp2p P2P networking in Go.

## Available Commands
- `/build "description"` - Design, implement, and review a feature or change
- `/test` - Run and fix tests

## Core Agents (3)
- `architect` - Design protocols, data flows, MPC/threshold patterns
- `engineer` - Implement Go code following project conventions
- `reviewer` - Review for correctness, security, and Go best practices

## Loading Strategy
1. If input starts with `/`, load from `.claude/commands/`
2. Match keywords to agents in `.claude-library/REGISTRY.json`
3. Load `.claude-library/contexts/project.md` for domain context when needed

## Simplicity First
- Start with direct implementation before spawning agents
- Add complexity only when current approach fails
- Keep context minimal — load on demand
