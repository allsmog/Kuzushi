# Mode Parity Assessment

This document describes the current Rust execution surfaces for `kuzushi scan`,
the interactive shell, and `kuzushi run`. Historical TypeScript runtime notes
belong in migration ledgers, not in this current operator contract.

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
| Interactive views | N/A | ✓ | N/A | Workbench, Activity, replay/trace, and guided pickers are shell-only. Descriptor-declared model prompts can be reviewed from Planning with `p`; the Vim-lite prompt document saves the existing workspace override and returns to Planning without launching work. |
| Machine output | ✓ | N/A | ✓ | Scan has CI/scripted output; headless `run` always prints the tool result as pretty JSON on stdout. |

## Intentional Asymmetries

- **Interactive shell views** are shell-only: Workbench, Activity dashboard,
  replay/trace, jobs registry, prompt tuning, actor detail, guided phase picker,
  model/auth pickers, and two-stage idle Ctrl+C.
- **Prompt/Navigate input modes are shell-only.** Prompt mode owns all printable
  text and submission. `F2` enters Navigate mode, where view bindings operate
  and printable keys never edit the command; `Esc` returns to Prompt mode.
- **Prompt preflight is shell-only.** Planning offers `p Review prompt` for a
  selected model-backed task only when its descriptor declares an editable
  prompt. The document opens in Normal mode (`j/k`, `Ctrl+f/b`, `gg/G`), `i`
  enters Insert mode, `:w` saves the project override, and `:q` returns to the
  unchanged Planning setup. Saving never launches the task.
- **Ordered onboarding gate is shell-only.** The interactive front door runs a
  single ordered gate — Target → Model → Credentials → Planning — via the pure
  `initial_onboarding_phase` fn. A bare `kuzushi` (no `--target`) opens the
  target picker first (only when `allow_target_gate` is set by the interactive
  launch); a missing API key opens the inline credential-entry step (API-key
  paste / OAuth / `d` offline demo) instead of dumping to the Workbench.
  `KUZUSHI_SKIP_ONBOARDING`, headless, and plain modes bypass the whole gate.
  Explicit-target consent (PR #64) is intact — nothing silently defaults to cwd.
- **Jobs registry + steer queue + background handoff are shell-only.** `jobs`
  (`ShellView::Jobs`) is a live control surface over the shared
  `.kuzushi/v3/runs/` format: it merges the single live `Run` (shared `JobHub`
  slot + `ActivitySession`) and queued steer items with recent on-disk
  `RunSummary` rows, de-duped by `run_id` (a disk `running` row with no live
  twin renders `Stale`/"running?"). `jobs -k <id>` dequeues a pending steer item
  or emits a scoped `CancelJob(JobKind)` that aborts only the addressed slot.
  The steer queue (`queue`, plus auto-queue of a `run` submitted while busy) is
  the lowest-precedence "next tool" mechanism — deterministic order **chain →
  plan → steer**, drained centrally in `apply_job_event` on every terminal job
  event and guarded against a pending chain/prereq-prompt/planning-queue. Only
  one live `Run` exists at a time, so queued items always render as pending,
  never running. `background`/`bg` (and Activity `b`) drops to the Workbench
  without cancelling. The CLI `runs list/show/trace` is the headless analogue
  over the same shared artefacts.
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
  findings-ledger projection. Filtering the visible Workbench list changes the
  composition, never the workspace totals or the current journey phase.
- **The PDF-exact phase cockpit is shell-only presentation.** Workbench pages
  `1`–`4` and guided Activity sessions render Map, Hunt, Confirm, and Fix from
  one `PhaseCockpitModel`; the shell's plain renderer flattens that same model.
  Activity retains the phase captured when work starts, while generic
  non-guided tools retain the standard Activity composition. Manual page
  navigation, pane zoom, and cinematic terminal styling never mutate the
  reality-derived journey phase or shared run/finding artifacts.
- **Verification replay is shell-only presentation over shared provenance.**
  The proof sidecar replays `verification_run_id`, never the finding's discovery
  `scan_id`, and labels proof inherited by a later scan as requiring
  revalidation.
- **DAG descriptors are not automatically execution ordering.** In the current
  Rust path, a `depends_on` edge is execution input only when the owning scan
  executor consumes it. Otherwise it is progress/catalog metadata.
- **Workbench confidence-first display sort is shell-only and hardcoded.** The
  Workbench findings pane re-orders the severity-major alias list by
  `compare_findings_by_confidence` (`confidence_first_display_order` in
  `crates/kuzushi-tui/src/ui_view_models/findings.rs`) before severity; there is
  no `setg`-controlled toggle back to severity-first, and scan/run output/exports
  keep the severity-major alias order.

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
