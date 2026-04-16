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

## Commits & Git Hooks

- Commit messages must pass `commitlint` (conventional-commits format). Allowed types: `feat, fix, chore, perf, refactor, docs, test, style, ci, build, revert, merge`.
- Header: `<type>(<scope>): <subject>` — max 100 chars, imperative mood.
- Pre-commit hook (`.husky/pre-commit`) runs `lint-staged` on staged files only (kept <5s). Full config: `commitlint.config.js` + `.lintstagedrc.json`.
- Escape hatches: `HUSKY=0` disables all hooks; `git commit --no-verify` bypasses for a single commit; `SKIP=<task>` skips a specific lint-staged task. See `docs/devex/05-conventions-assessment.md` for when each is acceptable.
- Activate the commit-message template locally: `git config commit.template .gitmessage`.

## Terminal UI (Ink)

- **All UI must go through the Ink shell.** Never use raw `readline`, `process.stdout.write`, or `console.log` for interactive terminal output. The Ink React app (`src/ui/App.tsx`) owns the terminal.
- UI state lives in `UIStore` (`src/ui/state.ts`). Components subscribe via `useUIState(store)`.
- UI modes: `"preflight"`, `"running"`, `"summary"`, `"review"`, `"done"`, `"shell"`. Each mode renders a different component tree in `App.tsx`.
- The copilot shell (`"shell"` mode) is rendered by `src/ui/components/CopilotShell.tsx`. Command logic lives in `src/copilot/shell.ts` — keep React components pure (display only).
- Non-TTY environments fall back to `src/ui/plain-renderer.ts` (subscribe-based console.log).
- New UI features: add state to `UIState`, create a component in `src/ui/components/`, wire it into `App.tsx` conditionally on `state.mode` or `state.phase`.

## Copilot Module System

- `CopilotModule` (`src/modules/types.ts`) is the pluggable capability unit. Each module exposes tools + optional tasks + knowledge.
- `ModuleRegistry` (`src/modules/registry.ts`) manages module lifecycle. Tools are namespaced as `module:action`.
- `CopilotCore` (`src/copilot/core.ts`) coordinates modules, dispatches tools, assembles agent context.
- The built-in `sast` module (`src/modules/core-sast.ts`) wraps the existing 40+ task pipeline.
- Three execution modes share the same core: pipeline (`kuzushi scan`), shell (`kuzushi` default), run (`kuzushi run`).

## Release Workflow

When releasing a new version:

```bash
# 1. Bump version in package.json
# 2. Stage, commit, tag
git add <files>
git commit -m "feat/fix/chore: description

git tag v<version>

# 3. Push
git push origin main
git push origin v<version>

# 4. Publish to npm
npm publish

# 5. Update global install
npm cache clean --force
npm install -g kuzushi@<version>
kuzushi --version
```

- Always bump `version` in `package.json` before publishing.
- Tag format: `v0.11.4` (prefixed with `v`).
- Wait a few seconds after `npm publish` if `npm install` returns `notarget` — registry propagation delay.
- Run `pnpm typecheck && pnpm test` before committing.

## Agent-Specific Notes

- Verify behavior in code; do not guess.
- Never edit `node_modules`.
- `MessageBus` and `AgentTask` are stable contracts; changes require explicit review.
