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
`triageAgentConfig`). `DagTool` is the DAG execution contract: scan-mode
registration stores module-owned `DagTool`s in `DagRegistry`, and workers call
`DagTool.run(input, ExecutionContext)` with `ctx.dag` populated.

### Key files

- `src/modules/types.ts` — `CopilotModule`, `ModuleTool`, `DagTool`,
  `ExecutionContext`, `DagContext`.
- `src/modules/host-handles.ts` — narrow handles (`HostUiHandle`,
  `ToolOptionStore`, `WorkspaceHandle`, `ModuleEventScope`, `ToolLogger`,
  `HostInfo`) exposed via `ExecutionContext`.
- `src/modules/define.ts` — `defineModule`/`defineTool`/`defineDagTool`
  authoring helpers with compile-time tool-name-prefix enforcement.
- `src/modules/dag-registry.ts` — native `DagTool` registry and DAG ordering.
- `src/modules/hidden-dag-node.ts` — helper for hidden built-in DAG nodes.
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

### Rust-native MCP servers (agent-callable)

Kuzushi also ships three Rust MCP servers that the pi-agent-core bridge
attaches as agent tools when a module asks for it:

- `crates/kuzushi-mcp-treesitter` — `tree_sitter:node_at`,
  `tree_sitter:query`, `tree_sitter:callers`. Pure-Rust, sub-10ms per
  call. Verifies AST structure of a candidate without spawning anything.
- `crates/kuzushi-mcp-joern` — `joern.taint_paths`, `joern.callers_of`,
  `joern.method_at`, etc. Lazy-spawns `joern --server` on first call
  under the MCP server's lifetime; honour `KUZUSHI_JOERN_CPG=<cpg.bin>`
  to importCpg the project at spawn time, or set `JOERN_SERVER_URL` to
  point at an operator-managed server. Schema includes regex examples
  for `source`/`sink` so the agent doesn't have to guess.
- `crates/kuzushi-mcp-codeql` — `codeql:flows_for_cwe`, `codeql:query`,
  `codeql:db_info`. Wraps `codeql database analyze` with an in-process
  result memo (same `(db, selector, limit)` returns instantly on
  repeat). Set `KUZUSHI_CODEQL_PREWARM=1` to pre-compile common CWE
  packs at MCP-server startup; set `KUZUSHI_CODEQL_CACHE_DIR=<path>` to
  share the on-disk pack cache across kuzushi runs.

The bridge wires these in when the request carries
`toolPolicy.mcps === true` (set by `taint-iris-next:hunt` automatically
via `AgentToolPolicy::with_mcps(true)`) or when the operator forces it
with `KUZUSHI_AGENT_MCPS=1`. Useful env vars when debugging:

- `KUZUSHI_BRIDGE_VERBOSE=1` — bridge stderr is drained on a background
  thread and forwarded to the parent's stderr in real time.
- `KUZUSHI_BRIDGE_LOG=<path>` — also append every bridge log line to
  `<path>` (useful when stdout is being captured by Rust).
- `KUZUSHI_MCP_TOOL_TIMEOUT_MS=<N>` — cap per-MCP-tool-call wall-clock
  so a runaway joern/codeql query surfaces as a tool error instead of
  hanging the agent loop.
- `KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS=<N>` — read by
  `scripts/taint_iris_next_flows.sc` so one catastrophic CWE doesn't
  deadlock the structural pass on a 187 MB postgres CPG.

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
  (`createDefaultDagRegistry`). New built-in modules that contribute DAG
  nodes must be added to that factory's module list so the scan CLI sees
  their tasks without needing full CopilotCore init.

### Clean Code / Uncle Bob baseline

Every code addition, refactor, merge, and conflict resolution should leave the
touched area easier for a human to understand and change. Treat this as a
standing review gate, not an optional cleanup phase.

- Keep modules cohesive: one clear responsibility, one primary reason to
  change. If a file starts coordinating unrelated concerns, extract named
  helpers or submodules with narrow APIs.
- Keep functions small enough to explain in one sentence. Prefer early returns,
  explicit names, and simple data flow over deeply nested control flow.
- Name concepts after the domain behavior they represent. Avoid vague names
  like `handleStuff`, `processData`, `utils`, or `manager` when a more precise
  tool, event, report, finding, scan, or approval concept exists.
- Preserve behavior before improving structure. For merges, integrate the
  useful branch behavior into the current architecture instead of accepting
  whole-file overwrites or resurrecting stale paths.
- Do not duplicate policy or parsing logic across scan, shell, and run modes.
  Extract shared helpers when behavior must stay identical.
- Keep side effects at the edges. Parsing, formatting, validation, and
  decision logic should be testable without filesystem, network, terminal, or
  model calls unless those effects are the feature under test.
- Prefer explicit errors and honest states over silent fallback. This is
  especially important for model/runtime selection, structured model output,
  scan findings, approval gates, and persisted `.kuzushi` artifacts.
- Add abstractions only when they remove real duplication or clarify a stable
  boundary. Do not introduce trait-heavy frameworks or generic "service"
  layers just to make code look abstract.
- Keep tests close to the behavior being protected. When extracting code from a
  large file, move or add focused tests for the extracted helper and keep the
  existing integration/snapshot tests passing.
- New or modified Kuzushi-owned production code must pass the repo CRAP-risk
  proxy gate with risk < 7. Keep functions at complexity <= 4 and under 40
  logical lines, isolate side effects behind adapters, and add focused tests for
  branchy behavior. If true CRAP tooling is available, use it as additional
  evidence, not as a substitute for the shipped gate.
- Before committing, scan the touched files for long functions, mixed
  responsibilities, unclear names, duplicated branches, stale comments, and
  needless public API expansion. Fix the local problem while the context is
  fresh.

### Domain-Driven Design baseline for Rust work

Use Domain-Driven Design to clarify Kuzushi's Rust security-agent domain, not
to add enterprise ceremony. Apply it when a boundary is already stable or when
logic is duplicated across CLI, TUI, reports, persistence, and tool execution.

- Keep Rust bounded contexts explicit: findings, scan, verification, modules,
  runtime governance, workspace, config/doctor/auth, reporting, and TUI shell
  application services.
- Prefer folders that make ownership obvious: `domain` for pure concepts and
  invariants, `application` for orchestration/use cases, `persistence` or
  `infrastructure` for IO/adapters, and `presentation` for labels, reports,
  aliases, and terminal-facing projections.
- Preserve stable public contracts while moving code. Compatibility `pub use`
  shims are acceptable during migrations; remove them only after downstream
  imports and tests are updated.
- Keep domain types free of terminal, filesystem, database, process, network,
  and model-provider side effects unless the effect is the domain concept under
  test.
- Centralize security invariants where users depend on them: finding identity,
  severity, evidence, proof state, verification result, scan/run artifacts,
  module/tool naming, and explicit model/no-fallback policy.
- Do not invent repositories, services, traits, or factories for trivial
  helpers. Add a DDD boundary only when it reduces real coupling, protects an
  invariant, or stops duplicated behavior.
- Specialist engines (`systems_hunt`, `carlini_threat_hunt`, `threat_model`,
  `x_ray`, `recon`, `repository_inventory`, `static_*`, `whitebox_*`, etc.)
  should stay internally coherent. Wrap them with thin adapters before
  rewriting their internals.
- TUI code should consume application services or presentation DTOs instead of
  opening stores or reimplementing findings/workspace/report logic directly.
- DDD refactors must preserve current CLI behavior, `.kuzushi` formats and
  paths, scan/shell/run parity, module/tool contracts, and model/runtime
  no-silent-fallback semantics.
- Every DDD migration should be phased, test-backed, and CRAP-aware: changed or
  newly introduced Rust functions must pass `pnpm quality:crap-risk`, or the
  commit must document a narrow blocker and avoid making the score worse.

### Model & runtime safety (no silent fallback)

Kuzushi will **never silently switch agent runtime, provider, or model**
without explicit operator consent. The Rust enforcement boundary lives in
`crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs`, the Rust
agent router rejects fallback chains, and `scripts/check-model-safety.mjs`
keeps those paths wired into CI.

Allowed fallbacks:
1. Same-model transport retries (network 5xx, rate limit 429) — handled
   inside each adapter, model object is reused.
2. Batch API → sequential per-prompt fallback — see
   the runtime execution helpers. The configured model is preserved.
3. Informational stale-model warnings. Banner only, never rewrites the model.
4. Backend defaults only when the operator has not configured a model at all.
5. Deterministic non-LLM fallback that is clearly labeled (e.g. extraction
   degradation in taint-analysis when `consentToExtractionLabelingFallback`
   is set).

Forbidden behaviors (caught by enforcement):
- Empty/missing `model` substituted with a backend default.
- Operator-configured model that is incompatible with the chosen runtime
  (e.g. `agentRuntimeBackend=codex` + `model=anthropic:claude-...`).
- Fallback model chains plumbed through provider or router configuration.
- Hardcoded `?? "anthropic:..."` defaults inside modules / orchestrator
  helpers — they bypass `ctx.config.model`.

When authoring a new module: derive the model from `ctx.toolModel ??
ctx.config.model` (or, in DAG tasks, via `resolveTaskModel(context, ...)`).
Never inline a literal model string as a runtime fallback.

### Operator control surfaces (flags, options, env)

See [docs/operator-control-surfaces.md](./docs/operator-control-surfaces.md)
for the operator-facing contract and precedence rules.

Tool/module behavior should flow through declared options, not scattered
environment variables or ad hoc JSON keys. Treat `OptionSpec` metadata and
`ModuleRegistry.prepareToolInput` / Rust `prepare_tool_input` as the canonical
tool-input boundary.

- Tool options are the source of truth for module behavior. Add new knobs to
  the tool descriptor first, with aliases only for compatibility.
- CLI flags are shorthands that compile into the same canonical tool input.
  Do not maintain a separate flag-only behavior path for scan, shell, or run.
- Config files are for durable runtime/provider defaults and workspace/global
  policy. They should not become a parallel per-tool option system.
- Environment variables are allowed for secrets and process integration:
  provider API keys/OAuth tokens, `PATH`/`HOME`/`EDITOR`, terminal or
  accessibility mode, test hooks, and documented emergency debug toggles.
- Do not add product behavior env vars for ordinary tool settings such as
  scanner binaries, budgets, MCP/CodeQL/Joern tuning, reasoning effort,
  plugin roots, or prompt knobs. Surface those as options or config fields;
  existing compatibility env vars should stay at config/adapter boundaries.
- Direct env reads belong at adapter/config/presentation boundaries. Domain
  types, module input parsers, scan engines, and runtime policy code should
  receive resolved values rather than reading `std::env` / `process.env`.
- Unknown tool input keys should not be accepted silently. Preserve backward
  compatibility through declared aliases/deprecated aliases, then validate at
  the canonical preparation boundary.

### Troubleshooting pointers

All `ModuleLoadError` codes and their fixes live in
[docs/modules.md §12](./docs/modules.md#12-load-errors--moduleloaderror).
The most common agent-facing surprises:

- `SHAPE_INVALID` with "does not start with" — the tool name lacks the
  module-id prefix; use `defineTool<"<id>">({...})` to catch at compile time.
- `ID_MISMATCH` — manifest `id` ≠ exported module `id`.
- `SDK_INCOMPATIBLE` — manifest `kuzushiSdkVersion` major drifts from host.

---

## Mode parity (scan / shell / run)

Audit + matrix in [docs/assessments/mode-parity.md](./docs/assessments/mode-parity.md).
The bullets below codify intentional asymmetries between the three modes —
features that *only* exist in one mode by design. Anything not listed here
is expected to behave identically and should be filed as a parity bug.

### Shared by all three modes

- `CopilotCore.executeTool(...)` is the single tool-dispatch path. `scan`
  also reaches it indirectly via bus workers; the contract (input
  validation, governance enforcer, audit-trail, runtime activity tee,
  capability probe, `resolveOption` fallback) is the same.
- `ExecutionContext.host`, `ctx.config`, `ctx.cwd`, `ctx.target`,
  `ctx.runtime`, `ctx.bus` are populated identically.
- Adaptive concurrency (`scheduler/configureRateLimitRegistry`) is seeded
  from `config.triageConcurrency` in **all three** modes (shell + run
  added in the parity audit; scan was the seed implementation).
- Prompt overrides in `.kuzushi/prompts/<moduleId>/<verb>.md` are
  auto-loaded by `core.executeTool`'s `resolveOption` fallback. Order:
  `Datastore` (shell-only) → `taskConfig[moduleId][KEY]` →
  on-disk file. So shell `set TRIAGE_PROMPT ./mine.md`,
  `kuzushi run` with `--input '{"TRIAGE_PROMPT":"…"}'`, and a checked-in
  `.kuzushi/prompts/triage/run.md` all reach the same tool the same way.
- `dataDir` resolution prefers `<target>/.kuzushi` when `--target`
  resolves to a directory (scan, run); shell falls back to
  `process.cwd()/.kuzushi` because its workspace lifecycle anchors there.

### Intentional asymmetries

- **Two-stage Ctrl+C, NL planner (`/plan`), prompt editor view, threat
  views, finding alias drill, replay/trace, cost-cap halt card, module-run
  transcript, actor-detail view, tune view** — interactive only. They
  live in the Rust Ratatui shell under `crates/kuzushi-tui`; plain/scripted
  output belongs in `crates/kuzushi-tui/src/renderer/plain.rs`.
- **`--ci` is scan-only.** Single-tool `kuzushi run` uses `--json` for
  machine-readable output; the shell is interactive by definition. Don't
  add `--ci` to `run`.
- **`/replay <runId>` and `/trace <runId>` are shell-only operator
  surfaces** that *consume* shared `.kuzushi/runs/<runId>/`
  artefacts. They are read-only over a shared on-disk format.
- **Pipeline-only artefacts are scan-only.** `kuzushi run` and shell tool
  dispatch now mint a `runId` and write `summary.json`, `trace.jsonl`,
  and input/result JSON. They do not produce scan-specific `triage.jsonl`,
  `verify.jsonl`, or `patch.jsonl` unless the tool itself emits them.
- **`ExecutionContext.workspace` handle is shell-only.** `kuzushi run`
  takes `--workspace <id>` (forwarded to tools that look the workspace
  up themselves) but does not wire the `WorkspaceHandle` capability —
  that needs the shell's `WorkspaceManager` lifecycle.
- **`ExecutionContext.datastore` is shell-only.** Scan + run modes
  consult `taskConfig` and the on-disk prompt files via
  `ctx.resolveOption`; they don't expose a live key/value store. New
  agentic capabilities should read through `resolveOption`, not from
  `ctx.datastore` directly.
- **`ExecutionContext.uiStore` is for live UI feedback only.** Scan
  workers populate it; run mode leaves it undefined; shell wires it for
  TTY paths. Tools must treat `uiStore` as optional (already enforced by
  the type and the `host.capabilities.has("ui-store")` probe).
- **`scan` mode loads only modules that contribute DAG nodes**
  (via `createDefaultTaskRegistry`). A module that exposes only
  shell-only `ModuleTool`s never has its `init()` called during scan —
  it isn't in scope for the pipeline. Use `createDagTool`/
  `exposeAgentTaskAsHiddenDagTool` to surface DAG-time work.

### When you add a new feature

1. Decide which mode(s) it belongs in. Default: all three.
2. If shell-only, gate it on `process.stdout.isTTY` and add a one-liner
   to the "Intentional asymmetries" list above.
3. If shared, add it to `core.ts` (or a helper consumed by `executeRun`,
   `startShell`, and `runPipeline`) — never duplicate config plumbing
   per mode.
4. Update the matrix in `docs/assessments/mode-parity.md`.

---

## Shell UX - Rust Ratatui Surface

The interactive shell (`kuzushi shell` or bare `kuzushi`) is Rust-native. The
operator-facing TUI lives in `crates/kuzushi-tui` and uses Ratatui plus
Crossterm. The old TypeScript/Ink render tree, mock TUI harness, TSX
components, and `src/copilot/shell.ts` are deleted. Do not add new interactive
shell behavior under `src/ui`, `src/ui/components`, `src/copilot/shell.ts`, or
any TypeScript/React/Ink path.

### Key Rust Files

- `crates/kuzushi-tui/src/app.rs` - `ShellApp`, `ShellView`, command handling,
  background events, view state, and tests for shell behavior.
- `crates/kuzushi-tui/src/app/state_transitions.rs` - extracted view
  transitions, scrolling, key handling, mouse handling, and spinner cadence.
- `crates/kuzushi-tui/src/commands.rs` - slash-command parser, aliases, and
  grouped help metadata.
- `crates/kuzushi-tui/src/renderer.rs` - Ratatui renderer and view-specific
  layout tests.
- `crates/kuzushi-tui/src/renderer/plain.rs` - non-TTY/scripted plain output.
- `crates/kuzushi-tui/src/theme/mod.rs` - semantic terminal styles.

### Shell Views

`ShellView` is defined in Rust, not TypeScript. Current variants include:
`Catalog`, `Module`, `ModuleRun`, `ActorDetail`, `Findings`, `Finding`,
`PromptsEditor`, `Plan`, `Threat`, `Replay`, `Trace`, `Activity`, `Help`,
`Config`, `Tools`, `Options`, `SastTasks`, `Context`, `Workspace`,
`KnowledgeBase`, `AgentChat`, `History`, and `Story`.

### Operator Verbs

The command source of truth is `SHELL_COMMAND_SPECS` in
`crates/kuzushi-tui/src/commands.rs`. Do not maintain a second TypeScript
router. Common verbs include:

- Navigation: `help`, `modules`, `tools`, `use <module>`, `back`.
- Run/scan: `scan [target]`, `run <tool> [json]`, `ask <question>`.
- Options/tasks: `options [tool]`, `set`, `setg`, `unset`, `tasks`,
  `task <verb>`.
- Context/KB: `context <verb>`, `workspace <verb>`, `kb`, `attach`, `detach`,
  `reparse`.
- Findings/evidence: `findings`, `open <id>`, `since <ref>`, `show aliases`,
  `show runs`, `replay <runId>`, `trace <runId>`, `activity` (`/a`,
  `/progress`).
- Auth/config/model/session: `auth`, `provider`, `backend`, `model`, `cost`,
  `config`, `load`, `resume`, `history`, `clear`, `story`, `quit`.

### Live Module Progress (Activity view)

The `/activity` view (auto-opened on `scan` and `kuzushi run`, or via the
slash command) is a split-pane dashboard showing every running module's
DAG status on the left and a streaming `[module:verb]` reasoning feed on
the right. It is fed by `ctx.trace.step(kind, verb, label).emit()` calls
in producer code, plumbed through `ToolExecutionContext.trace`.

- **Producer authoring**: see `docs/modules.md` §7.1. Every DAG-participating
  Rust module emits at least `start` + `done` steps; multi-phase modules
  (`triage:run`, `verify:finding`, `agentic-sast:scan`, `taint-iris:hunt`,
  `carlini-threat-hunt:run`, etc.) emit reasoning sub-steps via
  `trace.child(parent)`.
- **Hidden modules** (`pipeline:*`, `systems-hunt:*`, `context-lite:index`)
  collapse into one aggregated `subsystems` row. Their events stay out of
  the feed unless `V` (verbose toggle) is pressed.
- **Schema**: `RunTraceStep` (v2) carries `module_id`, `verb`,
  `parent_step`, `severity`, `started_at_ms`. All optional, backwards-
  compatible with v1 trace.jsonl files.
- **Transport**: `BroadcastSink` writes to `<run>/trace.jsonl` AND fans
  events into an `mpsc::Sender<RunTraceStep>` consumed by
  `ShellApp::drain_trace_events` and applied to `ActivitySession` via
  `apply_step`.
- **Keys**: `j`/`k`/`g`/`G` scroll, `Tab` toggles pane focus, `V` toggles
  verbose, `p` toggles pause, `R` resets, `Enter` focuses a task in the
  footer.

When adding a new producer module, follow the pattern in
`crates/kuzushi-core/src/modules/native_scanners/register_modules.rs::run_semgrep_scan`
(simple) or
`crates/kuzushi-core/src/modules/agentic_sast/run_agentic_sast_report.rs::run_agentic_sast_report`
(parent_step + child sub-steps).

### Live Module Progress — auto-tracing every LLM call

Producers don't have to manually log per-LLM-call events. The dispatch
wrapper (`src/modules/registry/with_v2_builtins/execution.rs`) wraps the
incoming `AgentRuntime` in a `TracedRuntime` (from
`src/runtime/traced_runtime.rs`) whenever `ctx.trace.is_some()`. Every
`runtime.query_blocking`, `next_step_blocking`,
`triage_finding_blocking`, or `spawn_subagent_blocking` call auto-emits
a `reasoning`/`tool-progress`/`done` step with `latency_ms` and
`cost_usd` populated from the provider response.

To group several LLM calls under a labelled phase header, wrap the
LLM region with a `TraceHandle::parent_scope(n)` RAII guard:

```rust
let phase = ctx
    .trace
    .map(|t| t.step("reasoning", "run", "evidence-collect").emit());
let _scope = match (ctx.trace, phase) {
    (Some(trace), Some(parent)) => Some(trace.parent_scope(parent)),
    _ => None,
};
// every runtime.query_blocking(...) inside this block now emits a
// child step under `phase` in the right-pane feed
let result = run_triage_stage2(store, runtime, &input, &config, kept)?;
drop(_scope);
```

Canonical references: `triage:run`, `verify:finding`,
`agentic-sast:scan`, `taint-iris:hunt`, `taint-iris-next:hunt`,
`carlini-threat-hunt:run`, `patch:finding`, `threat-model:build`,
`x-ray:run`, `run_plugin_finding_adapter`, `shinsa:scan`,
`prompt-armor:*`.

### Activity view auto-open

`ShellApp.auto_open_activity` defaults to `true`. Both
`start_background_tool` and `start_scan` set
`shell_view = ShellView::Activity` when the toggle is on. Operators can
opt out by exporting `KUZUSHI_AUTO_OPEN_ACTIVITY=false` before launching
the shell — the value is read in `ShellApp::new`. The view honours
independent pane scroll: `Tab` toggles focus between DAG/feed, `j`/`k`
operates on the focused pane, and manually scrolling the feed pauses
auto-tail until `p` (resume) or scroll-to-bottom.

### Plain And CI Output

Plain output for the Rust shell belongs in `crates/kuzushi-tui/src/renderer/plain.rs`.
Retained TypeScript files under `src/ui` are non-visual helpers for migration,
reference tests, summary/report formatting, and line-oriented scan output. They
must not grow a second interactive TUI.

### Adding A Shell View

1. Add the view variant and state to `crates/kuzushi-tui/src/app.rs`.
2. Add parser/help behavior in `crates/kuzushi-tui/src/commands.rs`.
3. Add reducer/key handling in `crates/kuzushi-tui/src/app/state_transitions.rs`
   when the view has custom navigation.
4. Add Ratatui rendering in `crates/kuzushi-tui/src/renderer.rs`.
5. Add or update plain/scripted output in
   `crates/kuzushi-tui/src/renderer/plain.rs`.
6. Add focused Rust tests in `crates/kuzushi-tui/src/app.rs`,
   `crates/kuzushi-tui/src/renderer.rs`, or `crates/kuzushi-tui/tests/`.

### Guardrails

- Do not add React, Ink, TSX, `src/ui/components`, `src/ui/primitives`,
  `src/ui/App.tsx`, `src/ui/render.ts`, `src/ui/setup.ts`, or
  `src/copilot/shell.ts`.
- Do not make TypeScript the CLI runtime path. `bin.kuzushi` points to the
  Rust wrapper, and `pnpm dev -- <args>` runs `cargo run -p kuzushi-cli --`.
- Keep non-TTY output useful: no ANSI requirement, no box-drawing dependency,
  no hidden interaction-only state.
- Preserve mode parity rules above when adding shell-only behavior.
