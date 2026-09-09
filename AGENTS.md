# Kuzushi agent guide

This guide is for AI/code agents working in Kuzushi. `CLAUDE.md` is a symlink
to this file; maintain one source of truth here.

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

All three should converge on `ModuleRegistry::prepare_dispatch_input(...)`,
bind any required explicit or interactive authorization, and then call
`dispatch_prepared_input_with_runtime(...)` (or its observed variant) in
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs`. That
boundary owns descriptor-driven option validation, stored-option merging, path
and prompt binding, authorization, trace scoping, runtime wrapping, and output
normalization. The raw `dispatch_prepared_tool_with_runtime(name, Value, ...)`
method remains a re-preparing compatibility wrapper. Mode-specific code may
prepare workspace/runtime/cancellation context, but it should not duplicate
tool policy or option parsing.

**Live built-ins are Rust descriptors plus Rust executors.** A capability is
registered as a `BuiltinModule` with `ToolDescriptor` values (`name`,
`description`, `headless`, `hidden`, `runtime_requirement`, `options`) and an
executor mapping under `crates/kuzushi-core/src/modules/`. `OptionSpec` is the
canonical input surface for user-facing knobs and aliases. DAG descriptors are
currently scan/progress metadata unless the owning executor consumes them
explicitly; do not assume `depends_on` alone changes execution order.

The repository ships no TypeScript SDK. Third-party module authors target the
published `schemas/module.manifest.schema.json` contract and the brokered KWP
Node worker protocol directly. When changing live product behavior, edit the
Rust descriptor/executor path first.

### Key files

- `crates/kuzushi-descriptor/src/descriptor_model.rs` —
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
- `schemas/module.manifest.schema.json` — published module manifest schema.

### Rust-native MCP servers (agent-callable)

Kuzushi also ships three Rust MCP servers that the pi-agent-core bridge
attaches as agent tools when a module asks for it:

- `crates/kuzushi-mcp-treesitter` — `tree_sitter:node_at`,
  `tree_sitter:query`, `tree_sitter:callers`. Pure-Rust, sub-10ms per
  call. Verifies AST structure of a candidate without spawning anything.
- `crates/kuzushi-mcp-cpg` — `cpg.taint_paths`, `cpg.callers_of`,
  `cpg.method_at`, `cpg.slice`, `cpg.scan`, etc. In-process cpg-rs
  engine (oxidized-joern): no JVM, no subprocess; reads the target from
  `KUZUSHI_MCP_CPG_ARTIFACT` and loads `<target>/.kuzushi/cpg-rs/`
  graphs, building them implicitly when absent. Schema includes regex
  examples for `source`/`sink` so the agent doesn't have to guess.
- `crates/kuzushi-mcp-codeql` — `codeql:flows_for_cwe`, `codeql:query`,
  `codeql:db_info`. Wraps `codeql database analyze` with an in-process
  result memo for dependency-free local query selectors. A memo hit skips
  `codeql database analyze`, but every request still performs full content
  authentication of the database tree, so memo-hit latency remains
  proportional to database size. Pack selectors bypass the result memo; local
  queries with imports are rejected because their dependency closure cannot be
  authenticated. On the first execution for a CodeQL bundle or database
  revision, the server copies the complete authenticated tree into an
  operator-owned session snapshot. Analysis and prewarm execute only
  OS-sandboxed snapshot paths; stale revisions cancel active work, normal
  shutdown drops the session, and startup reclaims abandoned sessions. Set
  `KUZUSHI_CODEQL_PREWARM=1` to pre-compile common CWE packs at MCP-server
  startup; set `KUZUSHI_CODEQL_CACHE_DIR=<path>` to share the on-disk pack cache
  across kuzushi runs.

The bridge wires these in when the request carries
`toolPolicy.mcps === true` (set by `taint-iris-next:hunt` automatically
via `AgentToolPolicy::with_mcps(true)`) or when the operator forces it with
the adapter compatibility switch `KUZUSHI_AGENT_MCPS=1`. Normal agent tools
declare `mcpToolTimeoutMs`, `bridgeVerbose`, and `bridgeLogPath` as descriptor
options. The adapter-only emergency hooks `KUZUSHI_BRIDGE_DEBUG_DUMP` and
`KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT` emit the same metadata-only diagnostic
projection; despite the latter's legacy name, it does not write prompt text.

### Load specifiers

Module specifiers take the `builtin:<id>`, `file://<abs-path>`,
`package:<npm-name>`, and `mcp:<server-spec>` forms, parsed by the Rust
dynamic loader. Rust built-ins are loaded from the Rust registry;
local `file://`/path modules go through digest-pinned `kuzushi.lock` approval
and the brokered KWP Node worker, while `package:` remains a trusted
compatibility path through the Rust dynamic loader and host script. Test both
paths through the real `ModuleRegistry` boundary before documenting behavior.

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

### Resource discipline for agents

- Search first, then read only the ranges needed to make a decision. Avoid
  repeatedly loading an entire large test or generated file into one session.
- Start with the narrowest relevant test. Use `pnpm verify:quick:summary` when a
  broad repository gate is necessary so child output does not flood agent
  history.
- If summary verification fails, rerun only the failing command to collect
  focused diagnostics before changing code.
- Treat subagent launches and multi-journey TUI audits as explicit operator
  decisions. Do not fan out one agent per journey unless the operator approves
  that parallelism.
- Run TUI DevEx journeys sequentially by default and name the requested journey
  IDs explicitly. An empty skill invocation runs only the highest-priority
  journey.

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
Rust `prepare_dispatch_input` as the canonical tool-input boundary.

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
  scanner binaries, budgets, MCP/CodeQL tuning, reasoning effort,
  plugin roots, or prompt knobs. Surface those as options or config fields;
  existing compatibility env vars should stay at config/adapter boundaries.
- Direct env reads belong at adapter/config/presentation boundaries. Domain
  types, module input parsers, scan engines, and runtime policy code should
  receive resolved values rather than reading `std::env` / `process.env`.
- Unknown tool input keys should not be accepted silently. Preserve backward
  compatibility through declared aliases/deprecated aliases, then validate at
  the canonical preparation boundary.

### Troubleshooting pointers

Current KWP load failures and fixes live in
[docs/modules.md § Troubleshooting](./docs/modules.md#troubleshooting). Common
causes are a tool name without its module-id prefix, missing descriptor policy,
an unlabeled path option, a changed digest without renewed approval, or a
protocol/host-version mismatch. There is no TypeScript `ModuleLoadError` API.

---

## Mode parity (scan / shell / run)

Audit + matrix in [docs/assessments/mode-parity.md](./docs/assessments/mode-parity.md).
The bullets below codify intentional asymmetries between the three modes —
features that *only* exist in one mode by design. Anything not listed here
is expected to behave identically and should be filed as a parity bug.

### Shared by all three modes

- Tool execution should pass through
  `ModuleRegistry::prepare_dispatch_input(...)`, authorization binding, and
  `dispatch_prepared_input_with_runtime(...)` (or its observed variant). The
  CLI, shell, and scan application code may differ in how they create
  workspace/runtime/cancellation context, but descriptor-backed option
  validation and output normalization live in the shared Rust registry path.
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

- **Approved local KWP dynamic modules are shell/run-only in v0.1.** Global
  `--load file://...` is consumed by the shell and `kuzushi run`; `kuzushi
  scan` rejects it instead of pretending the dynamic tool is a `sast:scan`
  task. KWP descriptors may carry inert phase metadata, but dynamic DAG
  scheduling remains future scan-orchestrator work.

- **Context-sensitive Ctrl+C/Ctrl+D exit and cancellation, NL planner
  (`/plan`), Setup editors, Run Focus, durable phase pages, Report,
  replay/trace, contextual visualizations, prompt tuning, actor detail, and
  cost-cap halt cards** are interactive shell presentation. Ctrl+C/Ctrl+D exit
  immediately when idle, request cancellation without exiting while work is
  active, and wait safely when cancellation is already pending.
  Plain/scripted output belongs in `crates/kuzushi-tui/src/renderer/plain/`
  and must serialize the same view models without inventing another workflow.
- **Cockpit Spine (`ShellView::{Setup,Workbench,Activity,Report}`)** is the
  canonical interactive workflow:
  `Target → Setup → Map ↔ Run Focus → Scan ↔ Run Focus → Review → Prove ↔ Run
  Focus → Fix ↔ Run Focus → Report`. `Workbench` hosts the five durable pages
  `Map`, `Scan`, `Review`, `Prove`, and `Fix`, not the retired generic four-pane
  command center. The canonical persisted/core enum is
  `WorkflowPhase::{Map,Scan,Review,Prove,Fix}`. Legacy `hunt` and `confirm`
  inputs load as deprecated `scan` and `prove` aliases for one major release;
  new artifacts serialize only canonical values. Merely visiting a page never
  advances reality.
- **Aggregate Setup (`ShellView::Setup`)** owns Target, Map plan, Model,
  Credentials, Prompt, Budget, and one `Start Map` action. Rows are evaluated in
  dependency order against the selected plan: deterministic runtime-free work
  may start without a model, while model-backed work requires an explicitly
  selected compatible model plus its real API-key, stored-OAuth, or session
  credential. An unset budget is `not enforced`; a set budget must be positive
  and within the hard ceiling. Editors restore Setup with plan, cursor, scroll,
  and prompt draft intact. Model selection is keyed by stable model id, never a
  catalog/visible-row index. Explicit Target consent is unchanged: Enter
  activates the selected candidate, Esc enters targetless capability browsing,
  and cwd is never substituted. Selected-candidate facts load asynchronously
  with a generation stamp and disclose path, repository/revision/dirty state,
  languages/build systems, nested scope, and prior Kuzushi artifacts; stale
  generations are discarded. Fresh or switched targets enter Setup; a
  hydrated engagement resumes its reality-derived phase page. `/setup` always
  reopens Setup explicitly.
- **Durable Map/Scan/Review/Prove/Fix pages** project persisted artifacts and
  finding truth. Map never reads live Run Focus state. A ready Map embeds the
  shared real-data gallery as its primary body: Summary by default after an
  accepted Map, then DFD — both permanent guidance surfaces that stay reachable
  with an honest empty state and a `threat-model:build` affordance — then Entry
  points and Components, which appear only when their artifacts exist.
  `Tab` changes the local projection; `z` opens the same projection in
  a Map-scoped full-frame zoom. Project context is one compact receipt, and the
  action drawer appears only for missing, stale, or blocked Map evidence. Scan
  is a resting cockpit over accepted attempts, scope/engine plan, per-engine outcomes,
  finding/artifact deltas, cost, freshness, and run references; live progress
  remains in Run Focus. Review keeps the confidence-first shell sort and
  displays authority, severity, proof, source count, confidence, and decisions.
  A pinned finding outside the current filter is disclosed by identity before
  any verify, suppress, patch, or apply action can target it. Prove places
  finding identity, `STATUS`, and the shared `NEXT` strip before evidence. Fix
  keeps the full draft → staged → applied → re-verification lifecycle visible
  rather than clearing the proof of application.
- **Engagement journey spine (`next`, phase rail, phase chip)** derives current
  Map/Scan/Review/Prove/Fix from durable current-target/current-revision
  evidence. Counts come from the unfiltered ledger, so filters and page visits
  never forge completion. Completed attempts require an explicit selection;
  partial Scan attempts additionally require acknowledgement. Clean Scan,
  all-rejected Review, and no-proof-backed Prove branches may truthfully offer
  Report. `workbench` routes to the derived page; `findings` and `open <id>`
  route to Review; `next` runs the current phase planner; `report` opens the
  dedicated Report exit. Journey/autonomy chrome is hidden until `Start Map`
  commits the engagement.
- **Autonomy dial chip + `Ctrl+↑`/`Ctrl+↓` chord** — shell-only chrome over a
  *shared* gate. The always-visible `⛭ <glyph> <rung>` posture chip
  (`ui_view_models/journey.rs::autonomy_footer_segment`, beside the phase chip,
  target-gated, with a `⚠` when it throttles the walker) and the raise/lower
  chord (`app/state_transitions/key_dispatch.rs::handle_autonomy_key`) are
  interactive-only. The *policy* is shared: the pure
  `modules::autonomy::gate(name, posture)` runs once in the shared prepared
  dispatch path and **only refuses** tools above the
  ceiling — it never redirects/substitutes a tool/model/runtime (no-silent-
  fallback safe). Posture rides `V2Config.autonomy` (serde-skip, in-process,
  default `Fix` = unconstrained so headless callers are unchanged). `kuzushi
  run --autonomy <recon|scan|review|prove|fix>` and the shell
  `autonomy`/`posture` verb set it; deprecated `hunt` and `confirm` remain input
  aliases for Scan and Prove during the compatibility window. Both clamp by
  `phases.stop_after`. Posture is orthogonal to the reality-derived journey
  phase — raising the dial never forges phase progress.
- **Security-viz gallery (`/scene`, `/viz`)** — interactive only
  (the rendering is TTY-bound), but **ungated and fed real Kuzushi data**. A
  `Tab`-cycled gallery of nine pages (`scene3d::VizPage`). Map directly embeds
  the Summary/DFD/Entry/Components subset; its `z` zoom retains that smaller tab
  scope, while explicit `/scene` restores the complete gallery. Pure view-model
  builders in `ui_view_models/viz_data.rs` turn `ShellApp` state into each
  page's model (`risk_by_module(&app.findings)`, `dfd_model(app)`,
  `entry_point_breakdown(app)`, `component_stack(app)`, `worklist_model(app)`,
  `attack_tree(app)`, `taint_flow_path(app)`); each model carries an
  `empty_hint` so a page with no
  backing artifact draws one guidance line, never dummy content. Rendered five
  ways:
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
    A dedicated **system summary** page pairs a source-grounded explanation of
    what the application does with aggregated trust-zone flows above a logical
    component tree; narrow terminals present the same content as one scrollable
    document. The tree groups DFD nodes by trust zone, distinguishes what each
    component does from why the application needs it, shows linked
    security-context counts, and lists each concrete flow once under its source.
    Its component cursor is shared by embedded Map and Map-scoped zoom: arrows
    select while the composer is empty, Navigate mode adds `j/k` and `g/G`,
    `PgUp/PgDn` pages relative to the selected component, and Enter opens that
    component as the selected DFD node. Selection survives Tab and zoom/back;
    accepting a new Map resets it to the first component.
    The separate DFD page opens directly on its node/flow/boundary graph; `j/k`
    reaches every concrete element and Enter opens its linked context. Plain
    output keeps the summary and DFD projections separate too.
  - **Entry-point browser** — the complete deterministic
    `.kuzushi/entry-points.json` catalog joined with
    `attackSurface.entryPoints[]` model annotations by stable surface id. Catalog
    path/line/kind/evidence remains authoritative; the model adds trust-zone
    context and DFD links without manufacturing links for every extracted row.
    The disposition-grouped master-detail browser distinguishes modeled,
    deprioritized, extracted-only, and model-only rows and reports extracted,
    selected, modeled, and linked counts plus exact catalog/model provenance.
    Stale, malformed, legacy-unverifiable, and changed-since-model catalogs are
    disclosed rather than presented as current. `j/k` selects every union row,
    `PgUp/PgDn` scrolls only its evidence, and `Enter` jumps when a resolved DFD
    node/flow/boundary exists. Wide terminals render list + detail side by side;
    narrow terminals stack a bounded list above the selected detail. Plain output
    remains exhaustive. The page appears when either backing artifact has rows.
  - **Component stack** — an asynchronously collected SBOM projection grouped
    as a tree by ecosystem, manifest/lockfile, scope, and component. Manifest
    constraints are labeled `declared`; lockfile values are labeled `resolved`,
    and matching resolved versions are shown beside direct dependencies. The
    page also names detected languages and build systems, appears only when real
    target facts exist, and uses the shared line-view scroll path.
  - **Line diagrams** — attack path (real source→sink stages from
    `app.taint_flow`) + findings heatmap (per-module risk) as styled box-drawing
    `Line`s in `renderer/views/scene/diagrams`.
  **Contextual auto-open:** `ui.auto_open_viz` remains on by default and
  `setg ui.auto_open_viz false` opts out (the compatibility environment value is
  read only at the adapter boundary). Non-Map visualizations are contextual
  full-frame decks over the workflow origin; Map's shared visualization is its
  native body and full-frame mode is only a zoom. A
  foreground completion first restores its exact origin, then opens the
  relevant non-empty deck; a background completion only emits a notice and
  never steals focus. Threat-model completion never force-opens the DFD;
  explicit `scene` access remains available. A completed foreground Map plan
  launched from Setup presents its durable Map result for explicit acceptance
  after the receipt is published. Other threat-model completions remain
  notification-only. `scan` maps
  to Heatmap when findings exist, and
  `viz_page_for_tool(tool_name)` maps artifact-emitting verbs exactly —
  `taint-iris:hunt`→AttackPath and `exploit-chain:scan`→ExploitChain. DFDs,
  entry-point inventories, component stacks, terrain, heatmaps, attack trees,
  and trace content therefore remain available without reviving the legacy
  Workbench layout.
  Prereq/read verbs
  (`taint-iris-next:catalog`, `threat-model:read`) and
  `taint-iris-next:hunt` (which flattens its path into finding text, emitting no
  `flows[]`) are intentionally unmapped. The snapshot caches
  in `app/tool_runner/run_tool/snapshots.rs` populate `app.exploit_chains` /
  `app.taint_flow` from the tool JSON `data` first; `taint-iris` emits structured
  `data.flows[]` for this (see `taint_iris` `extract_taint_flows`, parallel to
  the text findings). `VizPage::is_frame_rendered` (terrain, the two box-drawing
  pages, and the entry-point browser) drives `uses_scene_frame` ⇔ the frame-level
  path (`render_scene_view`); remaining line pages and all plain/non-TTY output
  go through `scene_page_lines` (frame pages show a "renders in a TTY" note
  there). All geometry and view
  models are pure and testable off-screen — `scene3d` rasterizer math, the
  `viz_data` builders, the diagram `Line` builders, and the box-drawing widgets
  (rendered into a `Buffer` in unit tests).
- **`--ci` is scan-only.** Single-tool `kuzushi run` always emits
  machine-readable JSON on stdout; the shell is interactive by definition.
  Don't add `--ci` or `--json` to `run`.
- **`/replay <runId>` and `/trace <runId>` are shell-only operator
  surfaces** that *consume* shared `.kuzushi/v3/runs/<runId>/`
  artefacts. They are read-only over a shared on-disk format. Finding proof
  stores `verification_run_id` separately from the discovery `scan_id`; the
  Prove proof sidecar replays only the verification run and warns when the
  proof belongs to an earlier observation of the same durable finding.
- **Prompt/Navigate modes are interactive-only.** Prompt mode owns printable
  input and submission. `Esc` on an empty prompt enters Navigate mode (with a
  draft, `Esc` first clears it), where view bindings operate without editing
  the prompt; `Esc` returns to Prompt mode. Runtime dispatch
  and rendered hints consume the same resolved keymap, including question and
  phase-result cards. A typed attention broker projects approvals, questions,
  credential gates, partial acknowledgements, and unresolved results into the
  footer and terminal title. Multiline paste remains one explicit submission:
  the composer shows a placeholder and expands the complete payload only when
  Enter is pressed.
- **Jobs registry (`jobs`, `ShellView::Jobs`), steer queue (`queue`),
  and background handoff (`background`/`bg`, Run Focus `b`)** — shell-only.
  `jobs` is a Metasploit-style live control surface over the shared
  `.kuzushi/v3/runs/` format: it merges the one live `Run` (from the shared
  single-slot `JobHub` + authoritative Run Focus session) plus queued items with
  recent on-disk `RunSummary` rows, de-duped by `run_id` (live supersedes its
  still-`running` disk twin; a disk `running` row with no live twin renders as
  `Stale`/"running?" muted, since its liveness can't be verified off-`/proc`).
  Operator/budget cancellation persists as `canceled`; watchdog escalation,
  process loss, and abnormal shutdown persist as `interrupted`. A requested
  cancellation stays visibly `canceling` until cleanup reaches a terminal row.
  `jobs -k <id>` dequeues a pending steer item, or emits a **scoped**
  `CancelJob(JobKind)` that aborts the addressed slot; `CancelActiveJobs`
  (Ctrl+C) additionally drains the steer queue and pauses the planning queue.
  Both go through the existing per-slot abort helpers — neither invents a second
  cancellation mechanism. The steer queue is the
  third and lowest-precedence "next tool" mechanism after the prereq chain and
  the planning queue — deterministic order is **chain → plan → steer**.
  `advance_steer_queue` drains centrally from `apply_job_event` on **every**
  terminal job event (scan/tool/agent/plan/threat, success or failure), and
  no-ops while work is running, a chain/prereq-prompt is pending, OR the
  planning queue is non-empty (its dispatch is deferred, so it must be guarded
  explicitly). Only one live `Run` exists at a time, so queued items always
  render as **pending**, never running. `kuzushi run` stays single-shot; the
  CLI `runs list/show/trace` is the headless analogue over the same shared
  artefacts. Run Focus captures the exact workflow origin before foreground
  launch. `b` restores that origin without cancellation; final chain/plan/steer
  completion restores it with one accumulated receipt. A completed Map attempt
  launched from Setup then opens its durable Map result, provided the exact
  current-target attempt is recorded and still unresolved; presenting it never
  selects it. Other origins, unsuccessful outcomes, manual Run Focus inspection
  and background-owned runs retain their existing return/focus policy.
- **Campaign deck (`campaign [id]`, `ShellView::Campaign`) is shell-only
  presentation over shared campaign artifacts.** It renders the same
  `plan.json` + `queue.json` fold as `campaign:status` (one snapshot
  implementation in `kuzushi-core::capabilities::campaign::snapshot`), adds
  cursor-driven include/exclude, worker-count, and prompt-preview interaction,
  and launches/kills a **detached** `kuzushi campaign run` dispatcher in its
  own process group (never in-process). Dispatched jobs are ordinary runs, so
  they appear in `jobs`/`runs` unchanged; headless parity is `campaign:status`
  plus `kuzushi campaign run`.
- **Contextual utilities are shell-only presentation.** Help, Controls, and
  Capabilities are modal; Jobs, Replay, Trace, and visualization pages are
  scrollable full-frame decks. They share one non-nesting origin: replacing one
  utility retains the original workflow view and input mode, and Esc restores
  both exactly.
- **The context rail (`rail`, `ui.rail`) is shell-only presentation.** A
  36-column right rail of ambient engagement facts (target/scope, attention
  items, journey chips, in-flight work, findings ledger, cost vs budget) that
  auto-appears at ≥140 columns — deliberately above the 120 that unlocks the
  Workbench Dense/Fix-reference layouts, so it never demotes them. Every rail
  section projects existing view-model truth; empty sections render nothing and
  the in-flight section self-erases. Body layout, breakpoints, hit-testing, and
  guided-question hosting all measure against the rail-reduced content area
  (`split_context_rail` in `renderer/render_app.rs`). `rail` toggles it with
  asymmetric persistence: hiding writes durable `ui.rail false`, showing
  restores auto policy plus a this-session force-open (floor 100 columns).
  Plain output never renders the rail.
- **Focus-gated attention notifications (`ui.notify`) are shell-only.** The
  interactive shell tracks terminal focus (crossterm focus events, enabled with
  bracketed paste) and, when a new `AttentionBroker` item appears while the
  terminal is blurred, rings BEL and posts an OSC 9 desktop notification. The
  policy (`app/attention_notify.rs`) fails closed while focus is unreported and
  returns structured skip reasons, never a silent bool; only static kind text
  leaves the frame. `setg ui.notify false` opts out; headless modes emit
  nothing.
- **Durable session transcripts are shell-only.** Interactive, plain, and
  scripted shells append a redacted semantic timeline under the operator-owned
  `~/.kuzushi/v3/sessions/` store. Headless `scan` and `run` keep their existing
  target-scoped run artifacts; transcript run events link to those artifacts by
  `runId` instead of duplicating their payloads.
- **Pipeline-only artefacts are scan-only.** `kuzushi run` and shell tool
  dispatch now mint a `runId` and write `run.json`, `items.jsonl`,
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
- **`scan` mode enters the Rust scan application and dispatches the
  `sast:scan` tool through the shared registry boundary.** Additional scan-time
  behavior belongs in Rust descriptors/executors or in explicit
  `sast:scan` orchestration, not in retired TypeScript task registries.

### When you add a new feature

1. Decide which mode(s) it belongs in. Default: all three.
2. If shell-only, keep it in the Rust TUI presentation/application boundary
   and add a one-liner to the "Intentional asymmetries" list above.
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

`ShellView` is defined in Rust, not TypeScript (the enum lives in
`crates/kuzushi-tui/src/app/view_state/sast_task_row.rs`). The cockpit routing
variants are `TargetPicker`, `Setup`, `Workbench`, `Activity` (presented as Run
Focus), and `Report`. `Workbench` owns the Map/Scan/Review/Prove/Fix page
selection; `Report` is an exit surface and never a sixth `WorkflowPhase`. `Catalog`,
`Keymap`, and `Help` are contextual modals; `Jobs`, `Replay`, `Trace`, and
`Scene` are contextual full-frame decks. Other diagnostic, configuration,
editor, picker, and approval variants remain supporting routes, not alternate
workflow spines. Do not restore the retired standalone Findings/Finding/Plan
routes or the generic whole-screen four-pane Workbench fallback.

### Operator Verbs

The command source of truth is `SHELL_COMMAND_SPEC_GROUPS` in
`crates/kuzushi-tui/src/commands/shell_command_specs/`. Do not maintain a
second TypeScript router. Common verbs include:

- Navigation: `help`, `modules`, `tools`, `use <module>`, `back`, `logs`
  (alias `log` / `transcript` — full-screen scrollable transcript with
  j/k/g/G/PgUp/PgDn).
- Run/scan: `full [target]` (`pipeline` alias), `run <tool> [json]`,
  `ask <question>`.
- Options/tasks: `options [tool]`, `set`, `setg`, `unset`, `tasks`,
  `task <verb>`.
- Context/KB: `context <verb>`, `workspace <verb>`, `kb`, `attach`, `detach`,
  `reparse`.
- Workflow: `setup`, `workbench`, `next` (`continue`), the exact phase verbs
  `map`, `scan`, `review`, `prove`, and `fix`, `findings`, `open <id>`, `report`,
  and `activity` (`/a`, `/progress`, presented as Run Focus).
- Evidence/utilities: `since <ref>`, `show aliases`, `show runs`,
  `replay <runId>`, `trace <runId>`, `jobs`, `scene`, and `viz`.
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
  The Report route presents the five formats in SARIF, Markdown bundle, JSONL,
  JSON, CSV order, defaults completeness to All, permits target-relative path
  editing, and keeps success/error receipts on screen. Finding exports
  additively include remediation application id, patch run id, lifecycle state,
  reverify outcome/run id, diff hash, and touched paths.
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

### Live Module Progress (Run Focus)

`ShellView::Activity` is presented as Run Focus. One `RunFocusModel` owns run
and sequence identity, planned/DAG task rows, current task, one clipped output
window, health/stall state, cost, queue depth, launch origin, steer editor, and
terminal receipt. Planned task identities are authoritative; do not rebuild a
second checklist from trace labels or special-case `context:build`.

Run Focus has one pure geometry contract shared by render, scrolling, and hit
testing: width ≥78 uses measured task/output content, keeping Steps/Output side
by side with Output at least 48 when both panes are useful, while sparse output
and materially wider task labels stack to preserve those labels. Width 50–77
stacks vertically with Steps content-sized and capped at 40% of the body; width
<50 or body height <14 uses one viewport and Tab switches Steps/Output.
Foreground Run Focus owns input in Navigate mode and reserves no generic prompt
row. `s` opens a compact editor that accepts only valid `run <tool> …`; `b`
backgrounds without cancellation and restores the captured origin.

- **Producer authoring**: see `docs/modules.md` §7.1. Every DAG-participating
  Rust module instruments its semantic task and calls; multi-phase modules
  (`triage:run`, `verify:finding`, `agentic-sast:scan`, `taint-iris:hunt`,
  `taint-iris-next:finding-review`, `carlini-threat-hunt:run`, etc.) emit bounded
  progress and safe reasoning beneath the owning task/call identity.
- **Schema**: `RunItemV1` is the sole durable execution lifecycle in
  `items.jsonl`, with stable item, task, call, question, and attempt identity.
- **Transport**: committed typed items fan out to `ShellEvent::RunItem`; the
  same durable stream drives `ActivitySession`, replay, plain mode, and CLI
  trace output.
- **Projection**: window the retained event ring before formatting and build
  output rows once per frame. Plain output consumes the same model and emits
  Steps followed by Output without side-by-side truncation.
- **Completion**: intermediate prereq-chain, plan, and steer receipts accumulate
  in deterministic chain → plan → steer order. The final terminal outcome
  restores the exact origin and shows one receipt with outcome, run count,
  duration, cost, changed findings/artifacts, and next action. A completed
  foreground Setup Map attempt then presents its durable Map result for
  explicit acceptance; its receipt and healthy current-target attempt projection
  must agree on completion and identity. Manual inspection and background-owned
  work never auto-return.

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
// child step under `phase` in the Run Focus output window
let result = run_triage_stage2(store, runtime, &input, &config, kept)?;
drop(_scope);
```

Canonical references: `triage:run`, `verify:finding`,
`agentic-sast:scan`, `taint-iris:hunt`, `taint-iris-next:finding-review`,
`carlini-threat-hunt:run`, `patch:finding`, `threat-model:build`,
`x-ray:run`, `run_plugin_finding_adapter`, `shinsa:scan`,
`prompt-armor:*`.

### Patch application and re-verification

`PatchResult` describes synthesis and disposable-worktree validation only; a
`SOUND` result is still merely a draft. Applying a reviewed diff appends a
`PatchLifecycleRecorded` v3 event keyed by `applicationId` and records target,
durable finding identity, patch run, diff/base commit, relative touched paths
with before/after hashes, actor, timestamps, state, and reverify provenance.
`patch:reverify` is descriptor-backed and headless. Its required
`applicationId` binds the originating detector and original prepared input at
the shared registry boundary; it refuses attribution after touched-file hashes
change and never substitutes a detector, runtime, provider, model, or target.
Only deterministic successful absence is `Verified`; rediscovery is
`StillVulnerable`, nondeterministic absence is `NotRediscovered`, and unavailable
comparison remains `Inconclusive`. Only `Verified` promotes the related patch
result to `PatchStatus::Verified`.

### Plain And CI Output

Plain output for the Rust shell belongs in `crates/kuzushi-tui/src/renderer/plain/`.
The repository contains no TypeScript runtime or SDK surfaces; do not
reintroduce one, and do not grow a second interactive TUI in JavaScript.

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
