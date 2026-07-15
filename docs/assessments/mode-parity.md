# Mode Parity Assessment

This document describes the current Rust execution surfaces for `kuzushi scan`,
the interactive shell, and `kuzushi run`. Historical TypeScript runtime notes
belong in migration ledgers, not in this current operator contract.

> Superseded UI assessment: the historical ordered picker gate, generic
> Workbench, Activity dashboard, and PDF-exact phase cockpit claims no longer
> describe the product. The current shell contract is the Cockpit Spine below.

## Shared Boundary

All modes should prepare and dispatch tools through the Rust module registry:

- `ModuleRegistry::prepare_tool_input(...)`
- `ModuleRegistry::dispatch_prepared_tool_with_runtime(...)`

The implementation lives under
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/`. Mode-specific
code may create workspace, runtime, trace, option-store, and cancellation
context, but descriptor-backed option validation and output normalization belong
to the shared registry boundary.

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
| Trace/run artifacts | ✓ | ✓ | ✓ | Tool dispatch writes the canonical run bundle plus prepared `input.json` and normalized `result.json`. A running summary exists before dispatch; completed, partial, skipped, failed, canceled, and interrupted remain distinct terminal outcomes. |
| Verification provenance | ✓ | ✓ | ✓ | Persisted proof carries both the verification run id and the discovery scan it verified. A later observation may reuse proof by durable identity, but is marked for revalidation; shell replay opens the verification run only. |
| Workspace target consent | ✓ | ✓ | ✓ | Workspace-backed commands require an explicit target such as `--target <path>` or `--target .`; modes must not silently substitute cwd. A live shell run keeps the target captured at launch even if ambient app state later changes. |
| Cancellation | ◐ | ✓ | ◐ | Shell/TUI work has live cancellation controls. Core scan engines accept cancellation tokens, but headless CLI scan/run do not currently install a dedicated SIGINT handler. |
| Plain/scripted output | ✓ | ✓ | ✓ | Plain output reuses the same projections as TTY output. Bare `--plain` emits a self-contained summary; scripted scan requires an explicit target, waits for terminal completion, writes its run bundle, and exits nonzero for invalid, partial, failed, canceled, or interrupted outcomes. |
| Interactive views | N/A | ✓ | N/A | Target, aggregate Setup, Map/Scan/Review/Prove/Fix, Run Focus, Report, and contextual utilities are shell-only. Prompt review returns to the unchanged Setup row without launching work. |
| Machine output | ✓ | N/A | ✓ | Scan has CI/scripted output; headless `run` always prints the tool result as pretty JSON on stdout. |

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
  text and submission. `F2` enters Navigate mode, where view bindings operate
  and printable keys never edit the command; `Esc` returns to Prompt mode.
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
- **`--ci` is scan-only.** Headless `kuzushi run` always emits JSON on stdout
  and writes run artifacts for machine consumers; it does not have a `--json`
  flag.
- **Pipeline JSONL artifacts are scan-owned.** All three write the canonical run bundle:
  `run.json`, `events.jsonl`, `trace.jsonl`, `failures.json`,
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
  patch artifacts are inferred without rewriting them.
- **Durable phase pages are shell-only presentation over shared truth.** Map
  never reads live Run Focus state. Scan is a resting cockpit over selected
  attempt, scope, engine outcomes, deltas, freshness, and run references; it is
  never live progress. Review keeps confidence-first display sort without
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
  never auto-navigate. Run trace schema and chain → plan → steer ordering remain
  shared and unchanged.
- **Contextual surfaces are shell-only.** Help, Controls, and Capabilities are
  modal; Jobs, Replay, Trace, and visualizations are scrollable full-frame
  decks. Replacing one utility retains the original workflow origin; Esc
  restores its exact view and input mode. Background visualization completion
  emits a notice and never steals focus.
- **Durable session transcripts are shell-only.** Interactive, plain, and
  scripted shell launches append a redacted semantic timeline under the
  operator-owned `~/.kuzushi/v3/sessions/` store. Headless `scan` and `run`
  retain their existing target-scoped run artifacts and do not create a shell
  session. Transcript events link to those artifacts by `runId` rather than
  copying their payloads.
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
