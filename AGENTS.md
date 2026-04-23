# CLAUDE.md

This guide is for AI/code agents (Claude, Codex, etc.) working in Kuzushi.

## Module system

For the full module-authoring guide — manifest, `defineModule`/`defineTool`
helpers, `ExecutionContext` reference, load specifiers, testing, MCP
bridging — see **[docs/modules.md](./docs/modules.md)**. What follows is
the minimum an agent editing this repo needs to know.

### Mental model

Kuzushi has one runtime core and three execution modes:

1. **scan mode** (`kuzushi scan`) — DAG pipeline execution.
2. **shell mode** (`kuzushi`) — conversational agent + tool dispatch.
3. **run mode** (`kuzushi run`) — headless single-tool execution.

All three converge on `CopilotCore.executeTool(...)` and the
`CopilotModule` / `ModuleTool` contract.

**One authoring surface.** Every capability is a `CopilotModule` that
exposes one or more `ModuleTool`s. DAG participants are `DagTool`s — a
narrow extension of `ModuleTool` with a `dag` block (`outputKind`,
`dependsOn`, optional `condition`/`promptMode`/`toolPolicy`/
`triageAgentConfig`). The legacy `AgentTask` type still exists as an
internal adapter shape but is no longer an authoring surface — new DAG
nodes go on a module via `defineDagTool` (visible) or
`exposeAgentTaskAsHiddenDagTool` (hidden infrastructure). The bridge at
`src/modules/dag-bridge.ts` turns these into `AgentTask` adapters so the
orchestrator's `TaskRegistry` sees them without authors needing to know.

### Key files

- `src/modules/types.ts` — `CopilotModule`, `ModuleTool`, `DagTool`,
  `ExecutionContext`, `DagContext`.
- `src/modules/host-handles.ts` — narrow handles (`HostUiHandle`,
  `ToolOptionStore`, `WorkspaceHandle`, `ModuleEventScope`, `ToolLogger`,
  `HostInfo`) exposed via `ExecutionContext`.
- `src/modules/define.ts` — `defineModule`/`defineTool`/`defineDagTool`
  authoring helpers with compile-time tool-name-prefix enforcement.
- `src/modules/dag-bridge.ts` — `exposeAgentTaskAsHiddenDagTool` helper
  plus the `registerDagToolsInTaskRegistry` bridge that auto-populates
  the orchestrator's `TaskRegistry` from a module's `tools[]`.
- `src/modules/errors.ts` — `ModuleLoadError` with `code` discriminator.
- `src/modules/loader.ts` — Zod-backed manifest validation + shape checks;
  enforces tool-name prefix and duplicate-name rejection.
- `src/modules/registry.ts` — lifecycle + tool resolution; validates
  `configSchema` against `moduleConfig` before `init()`.
- `src/modules/core-sast.ts` — canonical reference implementation; every
  pattern you'd want to copy lives here.
- `src/modules/mcp-bridge.ts` — MCP-server → `CopilotModule` adapter.
- `src/copilot/core.ts` — loader entrypoints + `ctx.host` injection.
- `src/testing/index.ts` — `kuzushi/testing` mocks.
- `schemas/module.manifest.schema.json` — published JSON schema.

### Load specifiers

`parseModuleSpecifier()` supports `builtin:<id>`, `file://<abs-path>`,
`package:<npm-name>`, `mcp:<server-spec>`. Bare strings default to builtin.

### Guardrails for agents editing this repo

- Do not break `CopilotModule`/`ModuleTool`/`DagTool` contracts without a
  migration plan (add a section to `RELEASING.md` + update
  `core-sast.ts` to stay exemplary).
- Preserve the `<moduleId>:<action>` tool-name convention — it's enforced
  at load time.
- Prefer adding behavior in the module/tool layer before touching
  orchestrator internals.
- Keep `headless` truthful: shell-only behavior should not be marked
  headless. `hidden: true` is for DAG-internal nodes that should not
  surface in `/use` or the LLM tool list.
- When adding fields to `ExecutionContext`, prefer narrow handles in
  `src/modules/host-handles.ts` over leaking internal host classes.
- If you add DAG-participating modules, include tests around dependency
  ordering (see `tests/modules/` + `tests/bus/orchestrator.test.ts`).
- Scan-mode bootstrap lives in `src/agents/index.ts`
  (`createDefaultTaskRegistry`). New built-in modules that contribute DAG
  nodes must be added to that factory's module list so the scan CLI sees
  their tasks without needing full CopilotCore init.

### Troubleshooting pointers

All `ModuleLoadError` codes and their fixes live in
[docs/modules.md §12](./docs/modules.md#12-load-errors--moduleloaderror).
The most common agent-facing surprises:

- `SHAPE_INVALID` with "does not start with" — the tool name lacks the
  module-id prefix; use `defineTool<"<id>">({...})` to catch at compile time.
- `ID_MISMATCH` — manifest `id` ≠ exported module `id`.
- `SDK_INCOMPATIBLE` — manifest `kuzushiSdkVersion` major drifts from host.

---

## Shell UX — Ink TUI surfaces (Phases A–C)

The interactive shell (`kuzushi shell` or bare `kuzushi`) is the main
operator surface. It uses React + Ink for rendering and a single
`ShellState.shellView` dispatcher to switch between sub-screens.

### Shell views

| View                 | Enter with                | What it renders                                     |
| -------------------- | ------------------------- | --------------------------------------------------- |
| `catalog`            | bare `kuzushi`            | Module catalog grouped by offense/intel/governance  |
| `module`             | `/use <id>`               | Per-module home: tools table, last-run, preset      |
| `findings`           | `/findings` or `/f`       | Unified findings list with filter chips + chains    |
| `finding`            | `/open F-NNNN`            | Linear deep page: state strip, evidence, timeline   |
| `tune`               | `/tune` or `/t`           | Six plain controls + optional "house rules" block   |
| `threat-dfd`         | `/threats dfd` or `1`     | ASCII DFD grouped by trust zone                     |
| `threat-stride`      | `/threats stride` or `2`  | Element × STRIDE heat matrix + impact × likelihood  |
| `threat-stories`     | `/threats stories` or `3` | Attacker narrative cards + input-categories rail    |
| `threat-scope`       | `/threats scope` or `4`   | Criticality buckets + out-of-scope + operator edits |
| `threat-summary`     | `/threats summary` or `5` | Counts bar charts + drives + artifact paths         |

Press `1..5` at any threat view to cycle without retyping the verb.
`/back` steps up one level (`finding → findings → module → catalog`).

### Operator verbs — full list

#### Module + view navigation

| Command                 | What it does                                        |
| ----------------------- | --------------------------------------------------- |
| `/modules`              | List loaded modules                                 |
| `/tools`                | List available tools                                |
| `/use <module>`         | Focus on a module; prompt becomes `kuzushi/<id>>`   |
| `/back`                 | Step back one view level                            |
| `/findings` (`/f`)      | Open the unified findings list                      |
| `/open <F-NNNN>`        | Open a finding in the linear deep page              |
| `/tune` (`/t`)          | Open tune view for the focused module               |
| `/threats [sub]`        | Threat-model views (see table above); bare = summary|
| `/threats edit`         | Open the full `ThreatModelEditor` (expert)          |
| `/since <ref>`          | Diff-aware view: findings scoped to git-changed files |

#### Natural-language planner (Phase A.1)

| Command                 | What it does                                        |
| ----------------------- | --------------------------------------------------- |
| `/plan <english>`       | Haiku translates intent → PlanCard with option diff |
| `/yes` / `y` key        | Apply the pending plan                              |
| `/no` / `n` / Esc       | Discard the pending plan                            |

#### Prompt editor (Phase A.2)

| Command                 | What it does                                        |
| ----------------------- | --------------------------------------------------- |
| `/prompt edit <verb>`   | Open `$EDITOR` on per-module prompt override        |
| `/prompt show <verb>`   | Show effective prompt + source (file/inline/default)|
| `/show prompts`         | Cross-module audit table of every `*_PROMPT` key    |

#### Replay / trace (Phase A.3)

| Command                 | What it does                                        |
| ----------------------- | --------------------------------------------------- |
| `/show runs [repo]`     | List recent pipeline runs (id · status · cost)      |
| `/replay <runId>`       | Re-render the summary of a past run                 |
| `/trace <runId>`        | Stream the per-event JSONL audit log                |

#### Short-ID aliases (Phase B.3)

| Command                 | What it does                                        |
| ----------------------- | --------------------------------------------------- |
| `/show aliases [prefix]`| List F-NNNN / C-NN aliases for the current run      |

Findings and chains get deterministic per-run aliases assigned from the
severity-sorted list (F-0001 = highest-severity finding; C-01 = highest-
severity chain). Operator-typed references (`/open F-0108`) resolve
through the alias map, with raw-fingerprint prefix fallback.

#### Failure-mode surfaces (Phase B.4)

- **Two-stage Ctrl+C at idle prompt** — first press arms, second press
  within 2s exits. Any other key disarms. In-flight work always aborts
  on first Ctrl+C (no change from before).
- **Rate-limit banner** — auto-renders above `StatusFooter` when
  `state.throttle` is set by the adaptive concurrency registry.
- **Cost-cap halt card** — `c` continues past budget, `a` aborts. Both
  reuse `shell.onAbort` for the abort path.

#### CI mode (Phase B.5)

- `kuzushi scan ./repo --ci` — disables Ink, attaches
  `src/ui/ci-stream.ts` for one-line-per-event output:
  `[2026-04-20T14:20:12Z] stage: scan → done (8.3s)` etc.
- `buildPrComment(summary, { repoName, runUrl })` — markdown
  PR-comment formatter in `src/report-pr-comment.ts`. Pipe to
  `gh pr comment -F -`.

### On-disk artefacts operators can version-control

| Path                                          | Produced by                    |
| --------------------------------------------- | ------------------------------ |
| `~/.kuzushi/config.json`                      | `/config`, setup wizard        |
| `.kuzushi/threat-model.json`                  | `randori`; edited by operators |
| `.kuzushi/house-rules/<moduleId>.md`          | `/tune`; free-text nudges      |
| `.kuzushi/prompts/<moduleId>/<verb>.md`       | `/prompt edit <verb>`          |
| `.kuzushi/runs/<runId>/summary.json`          | scan worker                    |
| `.kuzushi/runs/<runId>/triage.jsonl`          | audit-worker                   |
| `.kuzushi/runs/<runId>/verify.jsonl`          | audit-worker                   |
| `.kuzushi/findings.sqlite3`                   | scan + shell persistence       |

### Adding a new shell sub-view

1. Add the view id to `ShellView` union in `src/ui/state.ts`.
2. Add a case in `shell.ts`'s slash-command handler that routes to the
   new `shellView` (probably via a `resolve<Name>View()` helper for
   consistency — see `resolveThreatView`).
3. Add a component under `src/ui/components/<Name>View.tsx` that reads
   from `shell.*` via props.
4. Add a case in `ShellViewPanel` (`src/ui/components/CopilotShell.tsx`).
5. Add a one-line case in `src/ui/plain-renderer.ts` so the non-TTY
   path prints *something* when the operator enters the view.
6. If the view has cycle keybinds, add them to the `isThreatShellView`-
   style helper near the input handler.

### Testing conventions

- Pure helpers (e.g. `computeStrideCell`, `computeFindingAliases`,
  `buildPrComment`) get focused unit tests in `tests/ui/` or
  `tests/copilot/`. Target ≥ 5 cases per helper.
- Ink components render best via `ink-testing-library` when available;
  strip ANSI and snapshot the visible text.
- The shell test suite (`tests/copilot/shell.test.ts`) exercises the
  slash-command router; add an assertion there when shipping a new
  verb so the `/help` table and the handler stay in sync.
