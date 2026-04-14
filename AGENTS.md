# Repository Guidelines

- Repo: https://github.com/allsmog/Kuzushi

## Project Structure & Module Organization

- Source: `src/` — CLI entry in `src/cli.ts`, core types in `src/types.ts`, config in `src/config.ts`.
- Agents (primary abstraction): `src/agents/`
  - Types: `src/agents/types.ts` (`AgentTask`, `TaskContext`, `TaskOutputKind`)
  - Registry: `src/agents/registry.ts` (`TaskRegistry`, DAG resolution + cycle detection)
  - Factory: `src/agents/index.ts` (`createDefaultTaskRegistry()` — registers all native tasks including semgrep/codeql/agentic)
- Scanner implementations: `src/scanners/` — native task wrappers
  - Semgrep: `src/scanners/semgrep.ts`, `src/scanners/run-semgrep.ts`, `src/scanners/resolve-semgrep.ts`
  - CodeQL: `src/scanners/codeql.ts`, `src/scanners/run-codeql.ts`, `src/scanners/resolve-codeql.ts`
  - Agentic scanner: `src/scanners/agentic.ts`, `src/scanners/run-agentic.ts`
  - Scoring: `src/scanners/scoring.ts`
  - Types: `src/scanners/types.ts` (`Finding`, `TaskId`, `ScannerPlugin`)
- Event bus: `src/bus/` — transport-agnostic message bus + coordinator
  - Interface: `src/bus/types.ts`
  - Events: `src/bus/events.ts`
  - Orchestrator: `src/bus/orchestrator.ts` (DAG-aware stage execution)
  - Workers: `src/bus/workers/`
- Agent runtime abstraction: `src/agent-runtime/`
  - Contract: `src/agent-runtime/types.ts` (`AgentRuntime`, `AgentSession`, normalized messages/options)
  - Claude adapter: `src/agent-runtime/claude.ts` (`ClaudeSession` for subprocess reuse)
  - Batch file I/O: `src/agent-runtime/batch-files.ts` (`.kuzushi/batches/` read/write/cleanup)
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
  2. `resolveInitialTaskPlan()` determines enabled task IDs from `config.tasks` + transitive deps
  3. `resolveOrderWithPolicyEdges()` topological-sorts into parallel stage groups
  4. `runTaskDag()` executes each stage: publishes `task:start`, waits for `task:complete`/`task:error`
  5. Emit `stage:complete` per group
  6. Forward upstream outputs to dependent tasks via `TaskContext.upstreamOutputs`
  7. Continue triage/report pipeline
- Task events: `task:start`, `task:progress`, `task:complete`, `task:error`, `stage:complete`
- Finding events: `scan:finding` still emitted by scan worker for finding-producing tasks

## Adding a New Agent Task

1. Create `src/agents/tasks/<name>.ts` implementing `AgentTask<TInput, TOutput>`.
2. Pick `outputKind` and declare dependencies in `dependsOn`.
3. Register task in `createDefaultTaskRegistry()`.
4. If task needs config, read from `TaskContext.config` and optional task-specific config block.
5. Emit task-level progress through `TaskContext.bus` when useful.

## Configuration

- Layered precedence: defaults -> `~/.kuzushi/config.json` -> `<repo>/.kuzushi/config.json` -> CLI flags.
- Task selection: `config.tasks: TaskId[]` — the single public selection surface.
- Per-task config: `config.taskConfig: Record<string, TaskConfig>` — keyed by task ID or reserved stage ID.
- Stage model overrides: `taskConfig["triage"].model`, `taskConfig["verify"].model`, `taskConfig["poc-harness"].model` (replaces old top-level `triageModel`/`verifyModel`/`pocHarnessModel`).
- CLI: `--tasks <csv>`, `--task-model <taskId>=<model>`, `--preset <name>`.
- Key fields:
  - `model`, `tasks`, `taskConfig`
  - `agentRuntimeBackend` (`pi-ai`)
  - `severity`, `excludePatterns`
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
