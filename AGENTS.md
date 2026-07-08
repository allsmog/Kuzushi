# CLAUDE.md

This guide is for AI/code agents (Claude, Codex, etc.) working in Kuzushi.

## Module system

For the longer module and operator contract, see
**[docs/modules.md](./docs/modules.md)**. What follows is the minimum an agent
editing this repo needs to know.

### Mental model

Kuzushi has one live Rust dispatch boundary and three execution modes:

1. **scan mode** (`kuzushi scan`) — scan orchestration and selected scan-engine
   execution.
2. **shell mode** (`kuzushi`) — Rust Ratatui operator shell plus background
   tool dispatch.
3. **run mode** (`kuzushi run`) — headless single-tool execution.

All three should converge on `ModuleRegistry::prepare_tool_input(...)` followed
by `dispatch_prepared_tool_with_runtime(...)` in
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`. That
boundary owns descriptor-driven option validation, stored-option merging, trace
scoping, runtime wrapping, and output normalization. Mode-specific code may
prepare workspace/runtime/cancellation context, but it should not duplicate
tool policy or option parsing.

**Live built-ins are Rust descriptors plus Rust executors.** A capability is
registered as a `BuiltinModule` with `ToolDescriptor` values (`name`,
`description`, `headless`, `hidden`, `runtime_requirement`, `options`) and an
executor mapping under `crates/kuzushi-core/src/modules/`. `OptionSpec` is the
canonical input surface for user-facing knobs and aliases. DAG descriptors are
currently scan/progress metadata unless the owning executor consumes them
explicitly; do not assume `depends_on` alone changes execution order.

The TypeScript `src/modules` SDK remains as a compatibility/export surface for
third-party module authors and tests. It is not the runtime for built-in shell,
scan, or run behavior. When changing live product behavior, edit the Rust
descriptor/executor path first.

### Key files

- `crates/kuzushi-core/src/modules/descriptor/descriptor_model.rs` —
  `ToolDescriptor`, `OptionSpec`, `RuntimeRequirement`, and option metadata.
- `crates/kuzushi-core/src/modules/builtins/with_v2_builtins/` — Rust builtin
  registration, lookup, execution, DAG descriptors, and output normalization.
- `crates/kuzushi-core/src/modules/registry/` — registry facade and dispatch
  helpers used by CLI, TUI, and direct tool execution.
- `crates/kuzushi-core/src/modules/options/` — descriptor-backed option
  validation, coercion, defaults, aliases, and unknown-key rejection.
- `crates/kuzushi-core/src/modules/runtime_requirements.rs` — shared
  runtime-requirement policy consumed by CLI/TUI dispatch preparation.
- `crates/kuzushi-core/src/modules/dynamic_loader.rs` and
  `scripts/kuzushi-dynamic-module-host.mjs` — dynamic module bridge protocol.
- `crates/kuzushi-core/src/modules/application/sast_scan/` — SAST umbrella
  orchestration and post-scan triage/verify/patch continuation.
- `crates/kuzushi-cli/src/application/` — CLI scan/run/findings application
  services and mode-specific context preparation.
- `crates/kuzushi-tui/src/app/` — Rust shell state, command routing,
  background workers, and app services.
- `crates/kuzushi-tui/src/ui_view_models/` and
  `crates/kuzushi-tui/src/renderer/` — presentation DTOs and Ratatui/plain
  rendering.
- `src/modules/types.ts`, `src/modules/define.ts`, and `src/testing/index.ts`
  — retained TypeScript SDK/testing surface for external module authors.
- `schemas/module.manifest.schema.json` — published module manifest schema.

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

The retained TypeScript SDK exposes `parseModuleSpecifier()` for
`builtin:<id>`, `file://<abs-path>`, `package:<npm-name>`, and
`mcp:<server-spec>` forms. Rust built-ins are loaded from the Rust registry;
dynamic `file://`/`package:` loading goes through the Rust dynamic loader and
host script. Treat that bridge as a compatibility boundary and test it through
the real `ModuleRegistry` path before documenting new behavior.

### Guardrails for agents editing this repo

- Do not break public module/manifest contracts without a migration plan (add
  a section to `RELEASING.md`, update `docs/modules.md`, and keep the Rust
  descriptor/executor path exemplary).
- Preserve the `<moduleId>:<action>` tool-name convention. Rust built-ins,
  dynamic modules, command help, and visibility filtering all depend on it.
- Prefer adding behavior in the module/tool layer before touching
  orchestrator internals.
- Keep `headless` truthful: shell-only behavior should not be marked
  headless. `hidden: true` is for DAG-internal nodes that should not
  surface in `/use` or the LLM tool list.
- Add user-facing options to `ToolDescriptor.options` first; then consume the
  prepared/canonical input in the executor. Do not add a CLI-only, TUI-only, or
  env-only behavior path for ordinary product knobs.
- If a tool needs runtime/model/findings/workspace/cancellation behavior, keep
  that policy declarative and shared. Do not add per-mode allowlists unless the
  shared registry surface cannot express the behavior yet.
- If you add DAG metadata, include tests proving whether it is display metadata
  or execution-ordering input. Do not document `depends_on` as ordering unless
  the Rust executor consumes it.

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

Allowed behavior:
1. Same-model transport retries (network 5xx, rate limit 429) — handled
   inside each adapter, model object is reused.
2. Configuration/env bootstrap may materialize the operator's selected model
   before policy resolution. Once execution starts, missing or incompatible
   runtime-backed models are hard errors, not opportunities to choose another
   model.

Forbidden behaviors (caught by enforcement):
- Empty/missing `model` substituted with a backend default.
- Operator-configured model that is incompatible with the chosen runtime
  (e.g. `agentRuntimeBackend=codex` + `model=anthropic:claude-...`).
- Fallback model chains plumbed through provider or router configuration.
- Hardcoded `?? "anthropic:..."` defaults inside modules / orchestrator
  helpers — they bypass `ctx.config.model`.
- Tool-local model env vars such as `MODEL_<ROLE>` read directly from the
  process environment. Per-role model overrides must flow through
  `models.toml` or declared option-store keys such as `setg MODEL_<ROLE>`.
- Target-local model steering. `<target>/.kuzushi/v3/config.toml` must not set
  `model`, and `<target>/.kuzushi/models.toml` is rejected; model policy belongs
  to operator-owned config/models files, env bootstrap, or explicit tool input.
- Target-local model steering. `<target>/.kuzushi/v3/config.toml` must not set
  `model`, and `<target>/.kuzushi/models.toml` is rejected; model policy belongs
  to operator-owned config/models files, env bootstrap, or explicit tool input.

When authoring a new Rust module: use the shared model helpers
(`resolve_tool_model` for descriptor-backed module tools, or
`resolve_explicit_model` when a capability adapter has already parsed an
inline `model` value). Never inline a literal model string as a runtime
fallback.

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

- Tool execution should pass through
  `ModuleRegistry::prepare_tool_input(...)` and
  `dispatch_prepared_tool_with_runtime(...)`. The CLI, shell, and scan
  application code may differ in how they create workspace/runtime/cancellation
  context, but descriptor-backed option validation and output normalization live
  in the shared Rust registry path.
- `ToolExecutionContext` carries the same core Rust handles where they are
  available: `config`, optional `workspace`, optional `findings_store`, and
  optional `trace`. Tools must treat optional handles as optional and fail with
  explicit messages when a required capability is absent.
- Runtime/model policy is shared through Rust runtime helpers such as
  `runtime_requirements.rs`, `resolve_tool_model`, and no-silent-fallback
  validation. New agentic tools should derive the model from resolved tool
  input or `ctx.config.model`, never from hardcoded fallbacks.
- Prompt override files are not implicitly discovered for every tool call.
  A tool reaches an override when its descriptor exposes the prompt option and
  the prepared input carries inline prompt text or a path-like value. The TUI
  prompt editor can inspect project prompt files, but dispatch should not claim
  a hidden auto-load tier unless it is implemented in the shared registry path.
- Workspace state resolves from the active target root when a target-backed
  workspace exists; mode-specific fallbacks must be documented as intentional
  asymmetries.

### Intentional asymmetries

- **Two-stage Ctrl+C, NL planner (`/plan`), prompt editor view, threat
  views, finding alias drill, replay/trace, cost-cap halt card, module-run
  transcript, actor-detail view, tune view** — interactive only. They
  live in the Rust Ratatui shell under `crates/kuzushi-tui`; plain/scripted
  output belongs in `crates/kuzushi-tui/src/renderer/plain/`.
- **Workbench command center (`ShellView::Workbench`, verb `workbench`)** —
  the shell's default landing surface (set in
  `run_shell::open_start_view`, after the onboarding/target/model gates). A
  frame-rendered cockpit: wide terminals show
  `[SOURCE tree | CODE/DFD | FINDINGS | DETAILS]`; compact terminals collapse
  toward the review path so findings and detail text stay readable under the
  `Kuzushi · project · target · LIVE · phase` top bar. `Tab` cycles pane focus,
  `Shift+Tab` reverses it, `j/k` move the focused pane, and `Enter` pins or
  opens the focused finding. It folds the
  old standalone findings, finding-detail, and threat-DFD-tab surfaces — the
  `findings` and `open <id>` verbs route here. Interactive-only
  fidelity (bordered panes), but degrades to text via
  `renderer/views/workbench/render_workbench_view.rs::workbench_lines` for
  plain/non-TTY. `LIVE` lights while shell work is actually running (the shared
  `ShellApp::has_running_work` signal); pane focus lives on `app.workbench_focus`.
- **Workbench confidence-first findings sort is shell-only and hardcoded.**
  `confidence_first_display_order` in
  `crates/kuzushi-tui/src/ui_view_models/findings.rs` re-orders the
  severity-major alias list by `compare_findings_by_confidence` (`Confirmed`
  before `Unverified`, severity as tie-break) before it reaches the Workbench
  findings pane. There is no operator `setg` toggle back to severity-first, and
  scan/run output and `workspace:export-findings` keep the severity-major
  alias order untouched.
- **Launch-time target picker (`ShellView::TargetPicker`)** — interactive
  only, and now the **first phase of the ordered onboarding gate** (Target →
  Model → Credentials → Planning). A bare `kuzushi` (no `--target`) on a real
  TTY opens a picker (cwd + child repos/previous `.kuzushi` targets, via
  `discover_target_candidates`) before the model/credentials/planning chain;
  selection runs the same wiring as the `target <path>` verb and re-enters the
  gate. The decision is expressed in the pure `initial_onboarding_phase` fn via
  `OnboardingInputs::allow_target_gate`, which only the interactive launch
  (`run_shell::apply_launch_onboarding` → `ShellApp::launch_onboarding_phase`)
  sets `true`; construction and target activation pass `false`, so headless,
  plain-mode, and test apps keep the targetless default. `KUZUSHI_SKIP_ONBOARDING`
  short-circuits the whole gate inside the pure fn (no separate launch-site env
  check). Explicit-target consent (PR #64) is preserved — the picker only
  *offers* cwd as a candidate row, selection is an explicit Enter, and Esc
  opts into targetless browsing; nothing silently falls back to cwd. A missing
  API key opens the inline credential-entry step (`open_credential_entry`,
  reusing the `AuthMethodPicker` surface: API-key paste / OAuth / `d` offline
  demo) instead of logging a message and dumping the operator on the Workbench.
- **Engagement journey spine (`next`, phase rail, phase chip)** —
  shell-only operator orientation. `ui_view_models/journey.rs` derives the
  current 組 map → 崩 hunt → 作 confirm → 掛 fix phase from workspace reality
  (map artifacts on disk, findings, triage/verification state) and reconciles
  the live walker against that reality instead of forging completion. Home
  renders the rail + a phase-driven `▸ NEXT` line, status surfaces use the
  compact `組 map 1/4` style chip, and `next` (typed alias `continue`) reopens
  the phase walker at the derived phase. All of it is target-gated: no
  `--target`, no journey chrome.
- **Autonomy dial chip + `Ctrl+↑`/`Ctrl+↓` chord** — shell-only chrome over a
  *shared* gate. The always-visible `⛭ <glyph> <rung>` posture chip
  (`ui_view_models/journey.rs::autonomy_footer_segment`, beside the phase chip,
  target-gated, with a `⚠` when it throttles the walker) and the raise/lower
  chord (`app/state_transitions/key_dispatch.rs::handle_autonomy_key`) are
  interactive-only. The *policy* is shared: the pure
  `modules::autonomy::gate(name, posture)` runs once in
  `dispatch_prepared_tool_with_runtime` and **only refuses** tools above the
  ceiling — it never redirects/substitutes a tool/model/runtime (no-silent-
  fallback safe). Posture rides `V2Config.autonomy` (serde-skip, in-process,
  default `Fix` = unconstrained so headless callers are unchanged). `kuzushi
  run --autonomy <recon|hunt|confirm|fix>` and the shell `autonomy`/`posture`
  verb set it; both clamp by `phases.stop_after`. Posture is orthogonal to the
  reality-derived journey phase — raising the dial never forges phase progress.
- **Security-viz gallery (`/scene`, `/viz`)** — interactive only
  (the rendering is TTY-bound), but **ungated and fed real Kuzushi data**. A
  `Tab`-cycled gallery of five pages (`scene3d::VizPage`). Pure view-model
  builders in `ui_view_models/viz_data.rs` turn `ShellApp` state into each
  page's model (`risk_by_module(&app.findings)`, `dfd_model(app)`,
  `attack_tree(app)`, `taint_flow_path(app)`); each model carries an
  `empty_hint` so a page with no backing artifact draws one guidance line, never
  dummy content. Rendered three ways:
  - **3D attack-surface terrain** — half-block truecolor framebuffer with a
    z-buffer + Lambert shading (`scene3d::render`); one Gaussian bump per hot
    module, height = normalized severity-weighted risk score. The only page that
    animates.
  - **Box-drawing diagrams** — DFD as a node-link **data-flow graph** (from the
    persisted threat-model doc) and the exploit chain as an **attack tree** (from
    `app.exploit_chains`), painted into the `Buffer` with rounded `Block` node
    boxes + orthogonal connectors (`─ │ ╭ ╮ ╰ ╯` + `▶`/`▼` arrowheads) in
    `renderer/views/scene/diagram`. Crisp full-cell strokes — deliberately *not*
    the braille `Canvas` (which read grainy).
  - **Line diagrams** — attack path (real source→sink stages from
    `app.taint_flow`) + findings heatmap (per-module risk) as styled box-drawing
    `Line`s in `renderer/views/scene/diagrams`.
  **Auto-open:** mirrors `auto_open_activity`. On by default; opt out with
  `setg ui.auto_open_viz false` (the compatibility env var
  `KUZUSHI_AUTO_OPEN_VIZ=false` is still honored at the adapter boundary). When
  an artifact lands AND has content, the completion hooks switch the Activity
  output deck if it has not been manually pinned, and open/log the gallery page:
  `scan` → Heatmap (`apply_scan_finished`, only when findings > 0), and
  `viz_page_for_tool(tool_name)` maps the artifact-*emitting* verbs exactly —
  `taint-iris:hunt`→AttackPath, `exploit-chain:scan`→ExploitChain,
  `threat-model:build`→Dfd — in `apply_finished_tool_event` (fires before
  chain/queue advance so a follow-up tool's Activity view supersedes it; gated
  by `viz_page_has_content` so a zero-result run doesn't open an empty page).
  Prereq/read verbs (`taint-iris-next:catalog`, `threat-model:read`) and
  `taint-iris-next:hunt` (which flattens its path into finding text, emitting no
  `flows[]`) are intentionally unmapped. The snapshot caches
  in `app/tool_runner/run_tool/snapshots.rs` populate `app.exploit_chains` /
  `app.taint_flow` from the tool JSON `data` first; `taint-iris` emits structured
  `data.flows[]` for this (see `taint_iris` `extract_taint_flows`, parallel to
  the text findings). `VizPage::is_frame_rendered` (terrain + the two box-drawing
  pages) drives `uses_scene_frame` ⇔ the frame-level path (`render_scene_view`);
  the line pages and all plain/non-TTY output go through `scene_page_lines`
  (frame pages show a "renders in a TTY" note there). All geometry and view
  models are pure and testable off-screen — `scene3d` rasterizer math, the
  `viz_data` builders, the diagram `Line` builders, and the box-drawing widgets
  (rendered into a `Buffer` in unit tests).
- **`--ci` is scan-only.** Single-tool `kuzushi run` always emits
  machine-readable JSON on stdout; the shell is interactive by definition.
  Don't add `--ci` or `--json` to `run`.
- **`/replay <runId>` and `/trace <runId>` are shell-only operator
  surfaces** that *consume* shared `.kuzushi/v3/runs/<runId>/`
  artefacts. They are read-only over a shared on-disk format.
- **Jobs registry (`jobs`, `ShellView::Jobs`), steer queue (`queue`),
  and background handoff (`background`/`bg`, Activity `b`)** — shell-only.
  `jobs` is a Metasploit-style live control surface over the shared
  `.kuzushi/v3/runs/` format: it merges the one live `Run` (from the shared
  single-slot `JobHub` + `ActivitySession`) plus queued steer items with
  recent on-disk `RunSummary` rows, de-duped by `run_id` (live supersedes its
  still-`running` disk twin; a disk `running` row with no live twin renders as
  `Stale`/"running?" muted, since its liveness can't be verified off-`/proc`).
  `jobs -k <id>` dequeues a pending steer item, or emits a **scoped**
  `CancelJob(JobKind)` that aborts only the addressed slot (not every live job
  the way `CancelActiveJobs` does) through the existing per-slot abort helpers —
  it never invents a second cancellation mechanism. The steer queue is the
  third and lowest-precedence "next tool" mechanism after the prereq chain and
  the planning queue — deterministic order is **chain → plan → steer**.
  `advance_steer_queue` drains centrally from `apply_job_event` on **every**
  terminal job event (scan/tool/agent/plan/threat, success or failure), and
  no-ops while work is running, a chain/prereq-prompt is pending, OR the
  planning queue is non-empty (its dispatch is deferred, so it must be guarded
  explicitly). Only one live `Run` exists at a time, so queued items always
  render as **pending**, never running. `kuzushi run` stays single-shot; the
  CLI `runs list/show/trace` is the headless analogue over the same shared
  artefacts.
- **Pipeline-only artefacts are scan-only.** `kuzushi run` and shell tool
  dispatch now mint a `runId` and write `summary.json`, `trace.jsonl`,
  and input/result JSON. They do not produce scan-specific `triage.jsonl`,
  `verify.jsonl`, or `patch.jsonl` unless the tool itself emits them.
- **Rust `ToolExecutionContext.workspace` is an optional resolved
  `WorkspaceTarget`.** Workspace-backed tools must be given an explicit target
  by the mode that launches them. Do not silently substitute cwd.
- **Prompt overrides flow through the Rust option boundary.** Direct
  prompt-aware tools load `.kuzushi/prompts/<module>/<verb>.md` into their
  declared `_PROMPT` option when the caller did not pass that option
  explicitly. The `sast:scan` umbrella forwards its own
  `.kuzushi/prompts/sast/triage.md` and
  `.kuzushi/prompts/sast/verify.md` files into the internal triage/verify
  stages. New prompt knobs should be declared as `ToolDescriptor.options` and
  consumed from prepared input.
- **`ExecutionContext.uiStore` is for live UI feedback only.** Scan
  workers populate it; run mode leaves it undefined; shell wires it for
  TTY paths. Tools must treat `uiStore` as optional (already enforced by
  the type and the `host.capabilities.has("ui-store")` probe).
- **`scan` mode enters the Rust scan application and dispatches the
  `sast:scan` tool through the shared registry boundary.** Additional scan-time
  behavior belongs in Rust descriptors/executors or in explicit
  `sast:scan` orchestration, not in retired TypeScript task registries.

### When you add a new feature

1. Decide which mode(s) it belongs in. Default: all three.
2. If shell-only, gate it on `process.stdout.isTTY` and add a one-liner
   to the "Intentional asymmetries" list above.
3. If shared, add it to the Rust descriptor/executor path consumed by CLI,
   TUI, and scan application services. Keep config, option, runtime, and
   findings-store policy in shared helpers rather than duplicating it per mode.
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

- `crates/kuzushi-tui/src/app/` - `ShellApp`, `ShellView`, command handling,
  background events, view state, and tests for shell behavior.
- `crates/kuzushi-tui/src/app/state_transitions/` - extracted view
  transitions, scrolling, key handling, mouse handling, and spinner cadence.
- `crates/kuzushi-tui/src/commands/` - slash-command parser, aliases, and
  grouped help metadata; command specs live under
  `commands/shell_command_specs/`.
- `crates/kuzushi-tui/src/renderer/` - Ratatui renderer and view-specific
  layout tests.
- `crates/kuzushi-tui/src/renderer/plain/` - non-TTY/scripted plain output.
- `crates/kuzushi-tui/src/ui_view_models/routing.rs` and
  `crates/kuzushi-tui/src/ui_view_models/screen_context.rs` - view routing
  signals and screen-context projections consumed by renderer chrome.
- `crates/kuzushi-tui/src/theme/mod.rs` - semantic terminal styles.

### Shell Views

`ShellView` is defined in Rust, not TypeScript. Current variants include:
`Catalog`, `Module`, `ModuleRun`, `ActorDetail`, `Findings`, `Finding`,
`PromptsEditor`, `Plan`, `Threat`, `Replay`, `Trace`, `Activity`, `Help`,
`Config`, `Tools`, `Options`, `SastTasks`, `Context`, `Workspace`,
`KnowledgeBase`, `AgentChat`, `History`, and `Story`.

### Operator Verbs

The command source of truth is `SHELL_COMMAND_SPECS` in
`crates/kuzushi-tui/src/commands/shell_command_specs/`. Do not maintain a
second TypeScript router. Common verbs include:

- Navigation: `help`, `modules`, `tools`, `use <module>`, `back`, `logs`
  (alias `log` / `transcript` — full-screen scrollable transcript with
  j/k/g/G/PgUp/PgDn).
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

### Bug-bounty workflow surfaces (PR #64)

- **Explicit targets.** `workspace_for_target` no longer falls back to
  cwd. `kuzushi findings`, `kuzushi finding`, and `kuzushi shell` all
  require `--target <path>` (or `--target .` to opt into cwd). The TUI
  surfaces the active target in the top/status chrome.
- **Program scope.** Drop a `<workspace>/.kuzushi/scope.toml` with
  `[in_scope] hosts = […] cidrs = […]` and (optionally) `[out_of_scope]`
  to deny rules. When an allow list is present, unmatched targets are
  `OutOfScope`; deny-list-only files leave unmatched targets `Unknown`.
  Recon dispatch and the bounty importers refuse `OutOfScope` targets with an
  actionable error; the status footer shows a `scope: on` chip when the file is
  loaded.
- **Exports.** `workspace:export-findings` accepts
  `format=json|jsonl|sarif|csv|markdown-bundle`. SARIF emits one
  `runs[]` per `Finding.tool`; the markdown bundle is a directory
  (README.md from `build_pr_comment`, per-finding files, manifest.json).
- **Recon intake.** `recon:import {"tool": "amass|httpx|nuclei|nmap-xml",
  "path": "<file>"}` materialises the named export into the recon
  store. `doctor` warns when any of the optional binaries is missing.
- **Burp / HAR intake.** `bounty:import-har` and `bounty:import-burp`
  parse the corresponding capture into one `Finding` per request with
  `kind="http-request"` evidence (raw `request_blob` + `response_blob`
  carried on `finding_evidence`). Both gate on `scope.toml`.
- **Theme overrides.** `KUZUSHI_THEME=high-contrast` flips the palette
  to bright white + bold; `KUZUSHI_REDUCED_MOTION=1` pauses the spinner
  advance.
- **Adaptive footer.** Terminals below 70 columns wrap the keybind row
  to two lines instead of truncating behind a `+more` chip.

### Live Module Progress (Activity view)

The `/activity` view (auto-opened on `scan` and `kuzushi run`, or via the
slash command) is a split-pane dashboard showing every running module's
DAG status plus an ACTIONS strip on the left, and an OUTPUT deck on the right
with task detail, findings, and generated security artifacts. The feed rows are
fed by `ctx.trace.step(kind, verb, label).emit()` calls in producer code,
plumbed through `ToolExecutionContext.trace`.

- **Producer authoring**: see `docs/modules.md` §7.1. Every DAG-participating
  Rust module emits at least `start` + `done` steps; multi-phase modules
  (`triage:run`, `verify:finding`, `agentic-sast:scan`, `taint-iris:hunt`,
  `taint-iris-next:finding-review`, `carlini-threat-hunt:run`, etc.) emit reasoning sub-steps via
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
- **Keys**: `j`/`k`/`g`/`G` scroll the focused pane, `Tab` toggles pane focus,
  `←`/`→` switch output pages, `V` toggles verbose subsystem events, `p`
  freezes/resumes the feed, `R` resets presentation state, `Enter` focuses the
  selected task, and `o` opens the selected output artifact. Cancellation uses
  the global `Ctrl+C` chord or the `cancel`/`stop` command, not an Activity-local
  letter binding.

When adding a new producer module, follow the pattern in
`crates/kuzushi-core/src/modules/native_scanners/register_modules.rs::run_semgrep_scan`
(simple) or
`crates/kuzushi-core/src/capabilities/agentic_sast/application/run_agentic_sast_report.rs::run_agentic_sast_report`
(parent_step + child sub-steps).

### Live Module Progress — auto-tracing every LLM call

Producers don't have to manually log per-LLM-call events. The dispatch
wrapper
(`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`) wraps the
incoming `AgentRuntime` in a `TracedRuntime` (from
`crates/kuzushi-core/src/runtime/traced_runtime.rs`) whenever
`ctx.trace.is_some()`. Every
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
`agentic-sast:scan`, `taint-iris:hunt`, `taint-iris-next:finding-review`,
`carlini-threat-hunt:run`, `patch:finding`, `threat-model:build`,
`x-ray:run`, `run_plugin_finding_adapter`, `shinsa:scan`,
`prompt-armor:*`.

### Activity view auto-open

`ShellApp.auto_open_activity` defaults to `true`. Both
`start_background_tool` and `start_scan` set
`shell_view = ShellView::Activity` when the toggle is on. Operators can
opt out with `setg ui.auto_open_activity false`; the compatibility env var
`KUZUSHI_AUTO_OPEN_ACTIVITY=false` is still honored at the adapter boundary.
The view honours independent pane scroll: `Tab` toggles focus between
TASKS/OUTPUT, `j`/`k` operates on the focused pane, and manually scrolling the
feed pauses auto-tail until `p` resumes the feed or `G` jumps to the bottom.

### Plain And CI Output

Plain output for the Rust shell belongs in `crates/kuzushi-tui/src/renderer/plain/`.
Retained TypeScript files under `src/modules` and `src/testing` are SDK and
testing compatibility surfaces. They must not grow a second interactive TUI.

### Adding A Shell View

1. Add the view variant and state under `crates/kuzushi-tui/src/app/`.
2. Add parser/help behavior under `crates/kuzushi-tui/src/commands/`, including
   `commands/shell_command_specs/` when it is operator-facing.
3. Add reducer/key handling under `crates/kuzushi-tui/src/app/state_transitions/`
   when the view has custom navigation.
4. Add Ratatui rendering under `crates/kuzushi-tui/src/renderer/views/` and
   route it through `renderer/views/shell_view_lines.rs` or the frame renderer
   as appropriate.
5. Add or update plain/scripted output in
   `crates/kuzushi-tui/src/renderer/plain/`.
6. Update routing/context projections in `ui_view_models/routing.rs` or
   `ui_view_models/screen_context.rs` when top bars, footers, or plain output
   need to know about the new screen.
7. Add focused Rust tests in `crates/kuzushi-tui/src/app/tests.rs`,
   `crates/kuzushi-tui/src/renderer/tests.rs`, or `crates/kuzushi-tui/tests/`.

### Guardrails

- Do not add React, Ink, TSX, `src/ui/components`, `src/ui/primitives`,
  `src/ui/App.tsx`, `src/ui/render.ts`, `src/ui/setup.ts`, or
  `src/copilot/shell.ts`.
- Do not make TypeScript the CLI runtime path. `bin.kuzushi` points to the
  Rust wrapper, and `pnpm dev -- <args>` runs `cargo run -p kuzushi-cli --`.
- Keep non-TTY output useful: no ANSI requirement, no box-drawing dependency,
  no hidden interaction-only state.
- Preserve mode parity rules above when adding shell-only behavior.
