# Repository Guidelines

- Repo: https://github.com/kuzushi-dev/kuzushi

## Project Structure & Module Organization

- Source: `src/` — CLI entry in `src/cli.ts`, core types in `src/types.ts`, config in `src/config.ts`.
- Agents (new primary abstraction): `src/agents/`
  - Types: `src/agents/types.ts` (`AgentTask`, `TaskContext`, `TaskOutputKind`)
  - Registry: `src/agents/registry.ts` (`TaskRegistry`, DAG resolution + cycle detection)
  - Scanner adapter: `src/agents/scanner-adapter.ts` (`ScannerPlugin` -> `AgentTask`)
  - Factory: `src/agents/index.ts` (`createDefaultTaskRegistry()`)
- Scanners: `src/scanners/` — plugin-based (`ScannerPlugin` stays supported for scanner implementations)
  - Semgrep: `src/scanners/semgrep.ts`, `src/scanners/run-semgrep.ts`, `src/scanners/resolve-semgrep.ts`
  - CodeQL: `src/scanners/codeql.ts`, `src/scanners/run-codeql.ts`, `src/scanners/resolve-codeql.ts`
  - Agentic scanner: `src/scanners/agentic.ts`, `src/scanners/run-agentic.ts`
  - Scoring: `src/scanners/scoring.ts`
  - Registry: `src/scanners/registry.ts`
- Event bus: `src/bus/` — transport-agnostic message bus + coordinator
  - Interface: `src/bus/types.ts`
  - Events: `src/bus/events.ts`
  - Orchestrator: `src/bus/orchestrator.ts` (DAG-aware stage execution)
  - Workers: `src/bus/workers/`
- Agent runtime abstraction: `src/agent-runtime/`
  - Contract: `src/agent-runtime/types.ts` (`AgentRuntime`, normalized messages/options)
  - Claude adapter: `src/agent-runtime/claude.ts`
  - Runtime selector: `src/agent-runtime/index.ts`
- Triage: `src/triage.ts` (agentic triage via `AgentRuntime`, not SDK-bound).
- Store: `src/store.ts` (SQLite persistence via `better-sqlite3`).
- Report: `src/report.ts` (terminal output with chalk).
- Context utility: `src/context.ts`.
- Tests: `tests/`; bus tests in `tests/bus/`, agent tests in `tests/agents/`.

## Build, Test, and Development Commands

- Runtime: Node **22+**
- Package manager: pnpm
- Install deps: `pnpm install`
- Dev run: `pnpm dev` or `npx tsx src/cli.ts`
- Build: `pnpm build`
- Type-check: `pnpm typecheck`
- Tests: `pnpm test`
- Coverage: `pnpm test:coverage`

## Architecture: AgentTask + DAG

- `AgentTask` is the first-class execution unit:
  - `id`, `displayName`, `outputKind`, `dependsOn`, `run(input, context)`, optional `init(config)`
- `TaskRegistry.resolveOrder(enabledIds)` returns DAG stages as parallel groups.
- Orchestrator flow:
  1. `pipeline:start`
  2. Resolve enabled task DAG
  3. Execute each stage concurrently
  4. Emit `stage:complete` per group
  5. Forward upstream outputs to dependent tasks via `TaskContext.upstreamOutputs`
  6. Continue triage/report pipeline
- New generic task events:
  - `task:start`, `task:progress`, `task:complete`, `task:error`, `stage:complete`
- Backward compatibility:
  - Existing scan events (`scan:finding`, `scan:scanner-complete`, etc.) remain emitted for scanner-like tasks.
  - Existing `ScannerPlugin` implementations continue to work through `adaptScannerPlugin()`.

## Adding a New Agent Task

1. Create `src/agents/tasks/<name>.ts` implementing `AgentTask<TInput, TOutput>`.
2. Pick `outputKind` and declare dependencies in `dependsOn`.
3. Register task in `createDefaultTaskRegistry()`.
4. If task needs config, read from `TaskContext.config` and optional task-specific config block.
5. Emit task-level progress through `TaskContext.bus` when useful.

## Configuration

- Layered precedence: defaults -> `~/.kuzushi/config.json` -> `<repo>/.kuzushi/config.json` -> CLI flags.
- Key fields:
  - `model`, `triageModel`, `triageMaxTurns`
  - `agentRuntimeBackend` (`claude-sdk` today; `acp` reserved)
  - `scanners`, optional `enabledTasks`
  - `severity`, `excludePatterns`, `scannerConfig`
  - `busBackend`, `triageConcurrency`, `scanMode`

## Testing Guidelines

- Unit tests for DAG behavior belong in `tests/agents/`.
- Orchestrator integration tests belong in `tests/bus/` and should assert stage gating and dependency handoff.
- Run `pnpm test` before pushing when touching orchestration or task contracts.

## Security

- Never commit API keys or `ANTHROPIC_API_KEY` values.
- Do not commit findings DB files (`<repo>/.kuzushi/findings.sqlite3`).

## Agent-Specific Notes

- Verify behavior in code; do not guess.
- Never edit `node_modules`.
- `MessageBus` and `AgentTask` are stable contracts; changes require explicit review.
