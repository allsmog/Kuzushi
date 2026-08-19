# Mode Parity Assessment

This document describes the current Rust execution surfaces for `kuzushi scan`,
the interactive shell, and `kuzushi run`. Historical TypeScript runtime notes
belong in migration ledgers, not in this current operator contract.

> Superseded UI assessment: the historical ordered picker gate, generic
> Workbench, Activity dashboard, and PDF-exact phase cockpit claims no longer
> describe the product. The current shell contract is the Cockpit Spine below.

> Docs-parity gate: this file and [docs/OPERATOR.md](../OPERATOR.md) are the
> two documents the registry test
> `every_builtin_tool_is_documented_for_operators` searches — every
> registered built-in tool name must appear in one of them, so removing a
> tool mention here without adding it to the operator handbook fails the
> build.

## Shared Boundary

All registry-backed modes use the authorization-bound Rust module flow:

- `ModuleRegistry::prepare_dispatch_input(...)`
- bind any required explicit or interactive authorization
- `ModuleRegistry::dispatch_prepared_input_with_runtime(...)`, or the observed
  variant when the caller needs lifecycle artifacts

The implementation lives under
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/`. Mode-specific
code may create workspace, runtime, trace, option-store, and cancellation
context, but descriptor-backed option validation and output normalization belong
to the shared registry boundary. The raw
`dispatch_prepared_tool_with_runtime(name, Value, ...)` API remains a
re-preparing compatibility wrapper, not the pattern for new callers.

## Current Matrix

Legend: ✓ = present, ◐ = partial or tool-dependent, N/A = not applicable.

| Capability | scan | shell | run | Notes |
| --- | :--: | :---: | :-: | --- |
| Registry input preparation | ✓ | ✓ | ✓ | CLI scan compiles flags into `sast:scan`; shell and run prepare focused tool input through the same registry method. |
| Descriptor option validation | ✓ | ✓ | ✓ | `OptionSpec` aliases, defaults, coercion, and unknown-key checks are centralized where descriptors are present. |
| Stored tool options | ✓ | ✓ | ✓ | Global/workspace option stores are loaded before registry preparation. |
| Explicit input precedence | ✓ | ✓ | ✓ | Explicit JSON or command input overlays stored options. |
| Prompt override files | ◐ | ◐ | ◐ | Direct prompt-aware tools load `.kuzushi/prompts/<module>/<verb>.md` when the matching `_PROMPT` option is unset; `sast:scan` forwards its `sast/triage.md` and `sast/verify.md` overrides to internal stages. |
| Runtime no-silent-fallback policy | ✓ | ✓ | ✓ | Runtime-backed tools resolve a configured or explicit input model and fail on incompatible provider/runtime pairs; project-local model steering is rejected. |
| Findings store support | ✓ | ✓ | ✓ | Tools that require a store use the shared `tool_needs_finding_store` predicate before mode dispatch. Verification proof is attached by durable finding identity, not a scan-local row id. |
| Typed run lifecycle/artifacts | ✓ | ✓ | ✓ | Shared dispatch writes stable task/call identities to authoritative `items.jsonl`, plus prepared `input.json` and normalized `result.json`. One reducer drives live/replay/plain projections; terminal states and cost completeness remain distinct. |
| Staged-tool checkpoints | ✓ | ✓ | ✓ | Shared dispatch keys checkpoints from stable registry/descriptor/input/workspace fingerprints, reuses them only at the same known clean revision, and publishes them with durable unique-temp writes. `workspace:status` exposes pending coordinates and whether each checkpoint is reusable. |
| Verification provenance | ✓ | ✓ | ✓ | Persisted proof carries both the verification run id and the discovery scan it verified. A later observation may reuse proof by durable identity, but is marked for revalidation; shell replay opens the verification run only. |
| Workspace target consent | ✓ | ✓ | ✓ | Workspace-backed commands require an explicit target such as `--target <path>` or `--target .`; modes must not silently substitute cwd. A live shell run keeps the target captured at launch even if ambient app state later changes. |
| Cancellation | ✓ | ✓ | ✓ | Shell/TUI work has live cancellation controls, and core scan engines accept cancellation tokens. Headless `scan` and `run` each install the same two-stage SIGINT policy: the first Ctrl-C requests cooperative cancellation and settles a durable `canceled` terminal state with exit code 130, and a second Ctrl-C exits immediately with 130. |
| Plain/scripted output | ✓ | ✓ | ✓ | Plain output reuses the same projections as TTY output. Bare `--plain` emits a self-contained summary; scripted scan requires an explicit target, waits for terminal completion, writes its run bundle, and exits nonzero for invalid, partial, blocked, failed, canceled, or interrupted outcomes. |
| Interactive views | N/A | ✓ | N/A | Target, aggregate Setup, Map/Scan/Review/Prove/Fix, Run Focus, Report, and contextual utilities are shell-only. Prompt review returns to the unchanged Setup row without launching work. |
| Machine output | ✓ | N/A | ✓ | Scan has CI/scripted output; headless `run` always prints the tool result as pretty JSON on stdout. |
| Campaign planning (`campaign:plan` / `campaign:status`) | N/A | ✓ | ✓ | Deterministic workspace-file tools (no runtime): plan writes `.kuzushi/v3/campaigns/<id>/plan.json` + per-job prompt files; status folds the dispatcher `queue.json` and run `done.json` sentinels. Not a scan engine, so scan mode does not apply. |
| Campaign dispatch (`kuzushi campaign run`) | N/A | N/A | ✓ | Headless-only orchestrator: executes the plan as bounded `kuzushi run --run-id` child processes (own process groups) with the exit-code retry ladder, quota-wall pauses, and a budget cap; one exclusive dispatcher lease owns `queue.json`, recovery checks child process identity and terminal metadata, and unresolved provider spend halts new dispatch. |
| Campaign deck (`campaign [id]`) | N/A | ✓ | N/A | Shell-only presentation over the shared plan/queue snapshot fold; Launch/Kill manage a detached `kuzushi campaign run` dispatcher. Headless parity = `campaign:status` + `kuzushi campaign run`. |
| Campaign deck (`campaign [id]`, `ShellView::Campaign`) | N/A | ✓ | N/A | Shell-only presentation over the shared plan/queue snapshot fold (`capabilities::campaign::snapshot`, same fold as `campaign:status`); Launch/Kill manage a detached `kuzushi campaign run` dispatcher process group. Headless parity = `campaign:status` + `kuzushi campaign run`.The v2 deck additions (budget burn bar, per-job finding counts, quota-wall pause countdown) render fields the shared fold already carries (`budgetUsd` from `queue.json`, `findings` joined from each run's `run.json`), so `campaign:status` exposes the same data headlessly. |
| Coverage matrix deck (`coverage`, `ShellView::Coverage`) | N/A | ✓ | N/A | Shell-only presentation over the shared coverage fold (`capabilities::campaign::coverage`); read-only shards × threat-sources grid with per-shard finding counts. Headless parity = `campaign:coverage`. |
| Review backlog preset (`B` on Review, `c/f/d/w` one-key decisions; v2 adds `s`/`t` severity/tool filter chips, `X` confirm-guarded bulk defer, `u` single-level undo) | N/A | ✓ | N/A | Shell-only presentation toggle: untriaged-only rows in severity-major order with one-key decisions routed through the ordinary `decision <verdict> <reason>` reducer (watermark checks and pinned-finding disclosure unchanged). Bulk defer requires a second `X` to confirm and records one ordinary deferred decision per visible filtered finding; undo appends the inverse records (prior latest verdict, or needs_review) — history is never deleted, the latest-decision-wins fold makes the append a reversal, so a defer-then-undo leaves the trend/coverage folds unchanged. Decisions persist to the shared review-decision store, so headless `kuzushi findings` and exports see identical truth; the preset never alters the canonical confidence-first default sort. |
| Workspace trend strip (campaign deck + Report header) | N/A | ✓ | ✓ | One pure fold (`capabilities::campaign::trend`): FP rate = rejected-false-positive / decided findings (latest review decision wins, same reversal rule as the coverage confirmed fold), plus campaign spend and cost per confirmed finding. The shell renders `TrendMetrics::strip_label()` on the campaign deck list and the Report header; headless parity is the `trend` object on both `campaign:status` shapes. Zero denominators surface as `null`/`—`, and incomplete provider spend carries `providerSpendUnresolved` plus `>=$X` labels instead of masquerading as exact. |
| Trend history + sparkline (`.kuzushi/trend-history.jsonl`) | N/A | ✓ | ✓ | One history module (`capabilities::campaign::trend_history`) consumed by all three surfaces: `campaign:status` and deck/Report refreshes append a deduped snapshot (identical consecutive states never grow the file — the reason `campaign:status` is workspace-write, not read) and reload the bounded last-90 window. Shell renders a `HISTORY  fp ▁▂▇ · spend ▁▄█ · N snapshot(s)` strip under TREND on the deck and Report header; headless parity is `trendHistory` on both `campaign:status` shapes. Below two snapshots the strip is absent — no fake sparkline. |
| Confirmed-findings SARIF export (`report:sarif`) | N/A | ✓ | ✓ | Deterministic tool (no runtime, findings store required): exports only findings whose latest review decision is confirmed/to-fix (same reversal rule as the trend fold) as SARIF 2.1.0 — rules derived from CWE ids, severity→level mapping, and the workspace `trend` object carried as run properties. Distinct from `workspace:export-findings format=sarif`, which exports the whole ledger with full evidence/provenance properties regardless of review state. Empty store and no-decisions cases emit a valid empty SARIF run. |
| Pack linter (`pack:lint`) | N/A | ✓ | ✓ | Deterministic read-only tool (workspace optional): validates a knowledge pack — pack.toml shape, shard manifests (path existence + >50-file scope warnings when a target is active), threat-model schema (severity values, CWE well-formedness, threats present for planning, including compound `threat-models/` directories), prompt fragment `<module>/<verb>.md` destinations. Result fails on any ERROR row, so `kuzushi run pack:lint` exits nonzero (run-mode tool-failed contract). Not a scan engine. |
| Shard auto-suggest (`pack:suggest-shards`) | N/A | ✓ | ✓ | Deterministic workspace-write tool (no runtime): proposes trust-boundary shard candidates from directory file counts, language mix, entry-point identifier density, and test-vs-shipped heuristics; writes a commented draft to `.kuzushi/v3/reports/suggested-shards.toml` (never installs `.kuzushi/shards.toml`). Bounded walk (content-scan budget), stable density-then-path ordering. |
| Threat-intel research (`threat-intel:research`) | N/A | ✓ | ✓ | Descriptor-backed external action over an explicit workspace: bounded target-local package discovery → OSV queries → persisted CVE candidates → existing catalog harvest. The invocation discloses network use, bounds package/CVE counts, and never scans outside the selected target. `threat-intel:discover` remains its deterministic offline inventory-only counterpart. |
| Pipeline gate (`kuzushi ci`) | N/A | N/A | N/A | Headless-only CLI verb (like `kuzushi campaign run`, not a registry tool): read-only fold over persisted findings + review decisions + campaign artifacts. Gates on NEW confirmed findings (latest-decision confirmed/to-fix, shared `latest_confirmed_finding_ids` fold) vs the committed `.kuzushi/ci-baseline.json`, prints a plain summary, writes `.kuzushi/v3/reports/ci-summary.json`, and exits 0 clean / 1 gate tripped at `--fail-on` / 2 error. `--update-baseline` accepts the current confirmed set. Distinct from `scan --fail-on` (exit 3), which gates a single scan run's raw findings regardless of review state. |
| Review-yield corpus (`kuzushi review-yield census` / `kuzushi review-yield export --out <file>`) | N/A | N/A | N/A | Headless-only CLI verbs (like `kuzushi ci` and `kuzushi campaign run`, not registry tools): a fold over the recorded review decisions and finding observations of one explicit `--target` (the projection is opened read-write once so pending migrations run, then read through a read-only handle; the ledger is never rewritten). `census` counts every recorded decision and names every exclusion — automated/imported authors, policy outcomes, conflicting human reversals, no usable read cutoff, no pre-cutoff snapshot — and `--json` emits the same report machine-readably. `export` writes one JSONL row per durable identity plus a `<out>.manifest.json` sidecar carrying the label policy, frozen feature vocabulary, census, and a BLAKE3 digest over the manifest and every row; the destination must resolve inside the workspace root. The leakage firewall (`anchor <= cutoff < label` per row, whitelist feature deserialization, no raw identifiers, no exported workspace-root fingerprint) lives in `review_yield` core, so there is no shell/TUI surface to keep in parity and no scan-engine surface. |
| Split-verdict tie-break escalation (`verify:finding` `escalationModel`; deep-auditor `MODEL_TRIAGE_ESCALATION`) | ✓ | ✓ | ✓ | Shared pure policy (`runtime::decide_tie_break`): a split consensus escalates only to a DIFFERENT, operator-named model, never inherited. `verify:finding` reads the `escalationModel` option through the registry boundary in all three modes; the deep auditor resolves the `triage_escalation` router role from explicit sources only (`MODEL_TRIAGE_ESCALATION` / models.toml), never the operator/router default. Same-model or invalid escalations are refused and disclosed (verify: completed-with-warning + stage note; deep-audit: rationale suffix), and an inconclusive escalation keeps the verdict rather than forging one. Shell-only additions are presentation: the Prove card's escalate-on-tie ladder row and the tone-classified stage disclosure line. |

Patch application truth is shared durable state, not a shell-only inference.
`PatchResult` remains synthesis/worktree validation; the append-only
`PatchLifecycleRecorded` event records application and re-verification by
`applicationId`. The descriptor-backed, headless `patch:reverify` binds the
originating detector and original input through the registry, refuses changed
touched-file hashes, and never substitutes a detector, target, runtime,
provider, or model. Only deterministic successful absence is `Verified`;
nondeterministic absence is `NotRediscovered` and unavailable comparison is
`Inconclusive`. Export remediation fields are additive across every format.

## Intentional Asymmetries

- **Review-yield `within-band` and `learn` ordering is shell-only.** The `[review_yield]`
  section is ordinary global operator config that every mode loads, but only
  the interactive shell consumes it: it measures and explains interactive
  review, which `kuzushi scan` and `kuzushi run` do not perform. The ordering
  is applied in the confidence-first *display* path
  (`ui_view_models::findings::within_band_display_order`), which the review
  queue and plain output both inherit. `within-band` ranks a band by historical
  yield and `learn` by the model's knowledge gap (leaf entropy, then leaf
  support); both share one band walk and one eligibility rule, so neither
  crosses a proof-confidence or severity band, both freeze any band holding a
  row that lacks their own key, and both return the byte-identical baseline in
  every other mode. Learn's queue chip and detail explanation render through
  the same view models as every other pane, so plain output carries them
  verbatim; both are absent whenever no band is actually ranked. Two orderings are deliberately
  excluded: the backlog preset (worst-severity-first is its whole promise) and
  every export/CLI alias ordering (severity-major, unchanged in all modes).
  Exports disclose the session's mode and model id under
  `metadata.reviewYield` without claiming their rows were reordered. Protected
  by `app::review_session::tests::within_band::*` and
  `workspace::tests::export_metadata_*`.
- **The Cockpit Spine is shell-only presentation.** The route is
  `Target → Setup → Map ↔ Run Focus → Scan ↔ Run Focus → Review → Prove ↔ Run
  Focus → Fix ↔ Run Focus → Report`. Canonical persisted phases are
  `Map/Scan/Review/Prove/Fix`; Report is an exit surface, never a sixth
  workflow phase. Plain output flattens the same Setup, Run Focus, phase,
  receipt, and Report DTOs and prints commands for interactions it cannot
  perform.
- **Five interaction modes are shell-only chrome.** `Shift+Tab` cycles all
  five pages from Prompt or Navigate mode while retaining the shared draft and
  cursor. Navigate-mode `1..5` selects directly; `[` and `]` move panes. A
  selected mode is never phase truth, and Run Focus snapshots and displays its
  origin mode.
- **Prompt/Navigate input modes are shell-only.** Prompt mode owns all printable
  text and submission. `Esc` on an empty prompt enters Navigate mode (with a
  draft, `Esc` first clears it), where view bindings operate and printable
  keys never edit the command; `Esc` returns to Prompt mode.
- **Aggregate Setup is shell-only.** Target activation remains explicit. Setup
  evaluates Target, Map plan, Model, Credentials, Prompt, and Budget in
  dependency order and exposes one `Start Map` commit. Deterministic
  runtime-free plans may start without a model; model-backed tasks require the
  selected compatible model and its actual API-key, OAuth, or session
  credential. Editors restore cursor, scroll, plan selection, and prompt draft.
  Prompt save never launches work. Fresh/switched targets enter Setup; hydrated
  engagements resume their reality-derived phase page. Headless/plain callers
  do not gain an implicit cwd, target, model, credential, runtime, or provider.
- **Stable model identity is shared policy surfaced by Setup.** Reordered or
  filtered model lists resolve the configured stable model id to a visible row;
  highlight and Enter cannot refer to different catalog indexes.
- **Jobs registry + steer queue + background handoff are shell-only.** `jobs`
  (`ShellView::Jobs`) is a live control surface over the shared
  `.kuzushi/v3/runs/` format: it merges the single live Run Focus session and
  queued steer items with recent on-disk
  `RunSummary` rows, de-duped by `run_id` (a disk `running` row with no live
  twin renders `Stale`/"running?"). `jobs -k <id>` dequeues a pending steer item
  or emits a scoped `CancelJob(JobKind)` that aborts only the addressed slot.
  The steer queue (`queue`, plus auto-queue of a `run` submitted while busy) is
  the lowest-precedence "next tool" mechanism — deterministic order **chain →
  plan → steer**, drained centrally in `apply_job_event` on every terminal job
  event and guarded against a pending chain/prereq-prompt/planning-queue. Only
  one live `Run` exists at a time, so queued items always render as pending,
  never running. `background`/`bg` (and Run Focus `b`) restores the captured
  workflow origin without cancelling. The CLI `runs list/show/trace` is the
  headless analogue over the same shared artefacts.
- **The context rail is shell-only presentation.** A 36-column right rail of
  ambient engagement facts (target/scope, attention items, journey chips,
  in-flight work, findings ledger, cost vs budget), auto-appearing at ≥140
  columns — above the 120 that unlocks Dense/Fix-reference layouts so it never
  demotes them. `rail` toggles with asymmetric persistence (`ui.rail`); every
  section projects existing shared view-model truth; plain output never
  renders it.
- **Focus-gated attention notifications are shell-only.** New attention items
  ring BEL + OSC 9 only while the terminal is provably blurred (crossterm
  focus events; fails closed when focus is unreported). `setg ui.notify false`
  opts out. Headless modes emit nothing; the underlying `AttentionBroker` and
  its priorities remain shared truth.
- **`--ci` is scan-only.** Headless `kuzushi run` always emits JSON on stdout
  and writes run artifacts for machine consumers; it does not have a `--json`
  flag.
- **Pipeline JSONL artifacts are scan-owned.** All three write the canonical run bundle:
  `run.json`, `events.jsonl`, `items.jsonl`, `failures.json`,
  `report.md`, and `artifacts.json`, plus `input.json` and `result.json` for the
  dispatched tool. These are the shared tool input/result artifacts. SAST scan
  orchestration additionally owns declared
  `scan-input.json`, `triage.jsonl`, `verify.jsonl`, and `patch.jsonl` files;
  patch events do not share the verification log.
- **Umbrella scan identity is parent plus children.** Scan, shell, and run use
  the caller's context run id as the canonical `data.runId` for `sast:scan`.
  Engine-native ids remain under `data.runIds`. Core findings, findings count,
  CLI `--fail-on`, and scan-scoped SARIF use that full run-id union and
  de-duplicate by durable finding identity.
- **Interactive workspace lifecycle is shell-only.** The Rust
  `ToolExecutionContext` carries the same resolved `WorkspaceTarget` when a
  mode has an explicit target, but only the shell owns interactive workspace
  switching and picker lifecycle. The shell blocks target changes while work is
  live and asks the operator to retry after finish/cancel; activation
  atomically clears target-derived caches before hydrating the new workspace,
  so absent artifacts cannot leak from the previous target.
- **Journey chrome is shell-only.** Phase truth is derived from an unfiltered
  findings ledger, current target/revision, accepted phase attempts, review
  dispositions, proof records, and patch lifecycle. Filtering Review changes
  its visible rows, never workspace totals or phase. Journey/autonomy chrome
  remains hidden until `Start Map` commits the engagement; visiting Scan,
  Review, Prove, or Fix does not advance it. Legacy scan/triage/verification/
  patch artifacts are inferred without rewriting them. All five page names stay
  visible after engagement start; unavailable future pages carry an unavailable
  marker, but page cycling and direct selection can still inspect their honest
  empty state. Historical artifacts populate their corresponding page even when
  the next required phase has moved backward.
- **The relevant-finding corpus is mode-shared.** Review and default bulk triage
  consume all open, non-suppressed findings in the vulnerability database, not
  merely the findings attached to the selected Scan attempt. An explicit scan
  id still requests run-scoped triage. A nondeterministic miss preserves the
  prior observation; comparable deterministic lifecycle transitions may mark
  it stale. Chain construction uses that same relevant corpus and the latest
  review decision for a durable identity, so a later observation does not lose
  an earlier confirmed/to-fix decision. A newly accepted Map invalidates Scan
  completion ordering without deleting findings.
- **Durable phase pages are shell-only presentation over shared truth.** Map
  never reads live Run Focus state. A ready Map embeds the shared real-data
  gallery as its primary body: Summary by default after acceptance, then DFD,
  Entry points, and Components when backed by artifacts. `Tab` changes that
  local projection and `z` opens a Map-scoped full-frame zoom; project context
  is a compact receipt, while missing/stale/blocked evidence retains one action
  drawer. Scan is a resting cockpit over selected attempt, scope, engine
  outcomes, deltas, freshness, and run references; it is never live progress.
  Review keeps confidence-first display sort without
  changing export order. Review/Prove/Fix disclose a pinned finding outside the
  active filter before any action can target it. Prove keeps identity, STATUS,
  NEXT, proof, sources, and stale-proof warning in compact mode. Fix projects
  the append-only patch application/reverify lifecycle.
- **Operator questions are root-shell-only.** Only the interactive root agent
  loop receives the question tool and reliable one-shot response channel.
  Modules, subagents, bridge loops, scan/run headless execution, and
  `ToolExecutionContext` remain UI-free. An unexpected headless
  `request_user_input` call returns `INTERACTION_REQUIRED`; it never reads
  stdin or selects a recommendation. Background questions do not steal focus
  and appear in Jobs as `WAITING INPUT`. Planner questions execute inside the
  same capped model turn and resume planning after the answer; the UI retains a
  submitting card until the worker has persisted a terminal interaction
  receipt. Runtime keybinding overrides are likewise shell-only presentation:
  only home-scoped `operator.keybindings` may supply them, invalid reloads keep
  the last valid map, and hot reload does not re-resolve model/runtime policy.
  One typed attention broker projects approvals, questions, credential gates,
  partial-result acknowledgements, and unresolved result dispositions into the
  footer and terminal title without persisting prompt or secret text. Multiline
  bracketed paste is staged behind one visible placeholder and expands only on
  the operator's explicit submission; it is never split into automatic
  commands.
- **Run Focus is shell-only presentation over shared run artifacts.** One model
  owns the planned/DAG checklist and one clipped output window. Foreground
  runs capture route, phase/pane, input mode, scroll, pinned finding, and
  auto-return ownership. The final chain/plan/steer outcome restores that exact
  origin with one accumulated receipt; background and manually inspected work
  never auto-navigate. Typed lifecycle schema and chain → plan → steer ordering remain
  shared and unchanged.
- **Lifecycle semantics are mode-shared.** Scan, shell, and run all reach the
  typed stream through the shared preparation/dispatch boundary. Shell alone
  subscribes to committed items for Run Focus and operator questions.
  `events.jsonl` contains only non-authoritative compatibility diagnostics such
  as run-start and recovered-interruption summaries; it is never a replay
  source.
- **Contextual surfaces are shell-only.** Help, Controls, and Capabilities are
  modal; Jobs, Replay, Trace, and visualizations are scrollable full-frame
  decks. Replacing one utility retains the original workflow origin; Esc
  restores its exact view and input mode. Background visualization completion
  emits a notice and never steals focus. An interactive launch against a target
  with a persisted concrete DFD opens that DFD as the default deck (unless
  `ui.auto_open_viz=false`), with the reality-derived Workbench as its Esc
  origin. Map's `z` zoom preserves its smaller Summary/DFD/Entry/Components tab
  scope and selected projection; explicit `scene` restores the complete
  gallery. The DFD opens directly on concrete node, flow, and boundary
  inspection. Summary explains the application purpose, aggregate zone flows,
  and component purposes. Its tree cursor selects architectural components;
  arrows work with an empty composer, Navigate mode adds `j/k` and `g/G`, and
  Enter carries the selected component into the DFD. The cursor and its
  selection-relative scroll survive Map zoom/back.
  Threat-model *completion* remains notification-only and never
  force-opens a newly generated DFD. Other content-bearing tool mappings keep
  their contextual auto-open behavior.
- **Durable session transcripts are shell-only.** Interactive, plain, and
  scripted shell launches append a redacted semantic timeline under the
  operator-owned `~/.kuzushi/v3/sessions/` store. Headless `scan` and `run`
  retain their existing target-scoped run artifacts and do not create a shell
  session. Transcript events link to those artifacts by `runId` rather than
  copying their payloads.
- **Review yield is shell-only.** A review session records that an operator
  opened a finding to review it, so it can only be observed where interactive
  review happens, and the advisory explanation only means anything beside the
  finding it describes. `[review_yield]` is ordinary global operator config
  that `kuzushi run` and `kuzushi scan` load like any other section and then
  ignore; decisions they persist carry `reviewSessionId: null`. The event kind, the
  `review_sessions` projection table, and the
  `review_decisions.review_session_id` link are shared storage, readable by any
  mode. Neither `shadow` nor `visible` changes review order — proved
  byte-for-byte on the confidence-first path and the backlog bypass by
  `shadow_model_preserves_review_queue_order_byte_for_byte`,
  `shadow_model_preserves_backlog_order_byte_for_byte`, and
  `visible_mode_keeps_projected_order_byte_for_byte`; shell-only emission is
  proved by `no_model_configured_emits_no_session_and_null_session_on_decision`.
  `visible` is *not* an interactive-only rendering: the section is built from
  one view model and rendered through the shared detail-pane line path, so
  plain and scripted shells carry the same text with styles stripped
  (`visible_mode_renders_the_scored_state_in_styled_and_plain_output`).
- **Verification replay is shell-only presentation over shared provenance.**
  The proof sidecar replays `verification_run_id`, never the finding's discovery
  `scan_id`, and labels proof inherited by a later scan as requiring
  revalidation.
- **DAG descriptors are not automatically execution ordering.** In the current
  Rust path, a `depends_on` edge is execution input only when the owning scan
  executor consumes it. Otherwise it is progress/catalog metadata.
- **Review confidence-first display sort is shell-only and hardcoded.** Review
  re-orders the severity-major alias list by
  `compare_findings_by_confidence` (`confidence_first_display_order` in
  `crates/kuzushi-tui/src/ui_view_models/findings.rs`) before severity; there is
  no `setg`-controlled toggle back to severity-first, and scan/run output/exports
  keep the severity-major alias order.
- **Report is a shell-only exit over the shared export service.** It orders the
  existing formats SARIF, Markdown bundle, JSONL, JSON, CSV; defaults to All;
  cycles All/Open/Complete; and retains success/error receipts. Export records
  add remediation metadata in every format. Reveal Destination is an explicit
  operator action and has no headless side effect.

- **Deep-auditor dataflow degraded signifiers are shell-only presentation
  over a shared gate.** The `cpg_taint_paths` tool, the `taintTools` option, the
  readiness/query trace items, the `deep-audit:evidence` read API, and the
  `dataflow_evidence_rows` projection are all shared core; plain output inherits
  the Run Focus rows and the options table. Three surfaces are shell-only: the
  Health page `cpg graphs` row turning `Warn` with a "deep-audit runs grep-only;
  run cpg:build" disclosure when no graph exists, the transient run notice on a
  `Missing`-readiness deep audit, and the optional Review chip disclosing a
  degraded run from durable provenance.
- **The `AUDITED DATAFLOW` finding-detail / Prove section is shell-only
  presentation** over the shared `deep-audit:evidence` audit events. It renders
  after `EVIDENCE`, never displaces the P1 `MODEL LADDER`, and is empty (no
  header) when the auditor cited no dataflow evidence. Plain/scripted output
  reads the same projected rows.
- **Deep-auditor taint trace rows are shell-only Run Focus presentation** of the
  shared `ToolCallProgress`/`DiagnosticNotice` items the adapter emits (readiness
  once per audit, one coalesced query line per call, a `warn` degraded notice).
  `kuzushi run` and `triage:run` headless behave identically over the same items.
- **The Prove `MODEL LADDER` card and the Run Focus verify stage labels are
  shell-only presentation** over shared `verify:finding` data. The card
  (`ui_view_models/phase_cockpit/confirm.rs::investigation_model_ladder`) renders
  the drafted verification's `gate: <m> (rejection only)` / `panel: <m> x <N>
  pass(es)` / `escalate on tie: <m>` rows from the operator-stored `gateModel` /
  `model` / `escalationModel` / `VERIFY_PASSES` knobs, and previews the exact
  `run verify:finding {…}` the Enter-to-draft handler drafts (single source of
  truth — the preview can never diverge from what runs). Unset knobs read `not
  set` and are omitted from the drafted JSON. The tie-break stage labels (`gate ·
  plausibility (…) · rejection only`, `panel · N pass(es) (…)`, `escalation ·
  tie-break (…)`, plus a `refused` danger step) are the shared verify executor's
  own trace items; `replay`/`trace` and `kuzushi run` render the same ordered
  labels. An escalation-resolved split stays `ModelAssessed`/`Unverified` — the
  ladder rung never advances and no `Confirmed`/`runtime_verified` is forged.
- **The risk-worklist scene page and the `worklist` verb are shell-only
  presentation** over the shared `worklist:rank` projection.
  The scene Worklist page projects ranked rows (raw `A92`/`F17` citations,
  contributor states, `unranked` count, and the
  `⚠ degraded — no cpg graph` banner/chip); the page appears in the scene rail
  only when a `context-snapshot.json` exists (the EntryPoints gate-on-non-empty
  precedent), and `worklist` auto-opens it with contextual origin restore.
  Headless parity is `run worklist:rank`, which emits the same rows, citation
  raw/normalized pair, contributor states, and unranked list as machine-readable
  JSON.

## Current Parity Risks

- Per-tool policy still has mode-specific call sites. Runtime requirements and
  findings-store requirements are centralized; cancellation/SIGINT behavior,
  explicit-target checks, and related policy should follow the same
  descriptor-backed pattern.
- Hidden or descriptor-less tools can bypass strict option validation unless
  they declare their accepted input or the shared input boundary rejects unknown
  keys for them.
- Command discoverability depends on parser, handler, and help/spec metadata
  staying aligned. Tests should assert that every parsed shell verb is visible
  or intentionally hidden.
- View-models should stay pure or read through cached app services. Per-frame
  filesystem reads in TUI review surfaces are parity/performance bugs because
  plain and TTY output should observe the same data without repeated IO.

## Adding Shared Behavior

1. Add the user-facing knob to `ToolDescriptor.options` first.
2. Consume canonical prepared input in the Rust executor.
3. Put mode-independent policy in `crates/kuzushi-core/src/modules/` or a core
   application service, not in CLI/TUI allowlists.
4. Add a parity test that exercises scan, shell preparation, and headless run
   where the feature is expected to work in all modes.
5. If the feature is intentionally shell-only or scan-only, add it to the
   intentional-asymmetry list in this file and in `AGENTS.md`.
