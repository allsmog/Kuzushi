# State, waiting, and return-experience hardening proposal

Date: 2026-08-18
Stage: hardening-pass Stage 1 — proposal only
Source policy: production and test source were read only; this memo is the only file created.

## Verdict

KEEP the strict persisted-truth invariants. A Map or Scan checkpoint from a different revision or dirty state must not count as current, and an abandoned process must become `interrupted`, never successful. The defects are presentation and transition-reporting defects: Kuzushi has the information needed to explain both events but discards it before the shell can volunteer it.

Implement the first two workstreams before the follow-ons. They are independently shippable and file-disjoint except for the TUI hydration seam.

## Workstream 1 — disclose revision and dirty-tree checkpoint drift

### Re-verification

Supported. `PhaseTargetSnapshot::equivalent_to` deliberately requires canonical target, revision, and dirty-state equality (`crates/kuzushi-core/src/workflow_attempts/domain.rs:12-38`). `WorkflowAttemptLedger::selected_for` consequently returns no selected checkpoint after either value changes (`crates/kuzushi-core/src/workflow_attempts/ledger.rs:95-109,250-268`). `selected_attempt_counts` converts that absence into an incomplete Map or Scan checkpoint (`crates/kuzushi-tui/src/ui_view_models/journey.rs:243-271`), while the phase header exposes only the generic `next required Map` atom (`crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/header.rs:384-393`). The ledger already has target-only history semantics in `has_attempt_for_target` (`ledger.rs:58-80`), but no presentation-safe query for the most recent selected checkpoint on the same target.

The audit's exact phrase “N commits behind” is only supportable when the recorded commit is an ancestor of the current commit. It must not be fabricated for divergent history, force-pushes, missing objects, or dirty-only changes.

### Proposed change

1. Preserve `PhaseTargetSnapshot::equivalent_to`, `selected_for`, and the current journey gate unchanged. Stale evidence remains stale and never advances the rail.
2. Add a pure ledger query in `crates/kuzushi-core/src/workflow_attempts/ledger.rs`, named for its weaker identity contract, for example:

   `latest_selected_for_target_identity(phase, current_snapshot) -> Option<&WorkflowAttemptRecord>`

   It must match the canonical target only, require a selected/accepted disposition, and return the newest record. It must not fall back across targets and must not make the returned record current.
3. Add a core git comparison in `crates/kuzushi-core/src/workspace/git_metadata.rs`:

   `RevisionRelationship::{Same, AheadBy(u64), Diverged, RecordedRevisionUnavailable, CurrentRevisionUnavailable}`

   Resolve `AheadBy` with an ancestry check followed by `git rev-list --count recorded..current`. Run this only in asynchronous hydration, never from a view model or renderer. Dirty-state drift is a separate boolean transition because it can occur with `Same` revision.
4. Extend the off-frame git hydration in `crates/kuzushi-tui/src/app/view_hydration/reader.rs` and its key/request data in `app/view_hydration/{key.rs,requests.rs}` so the comparison is keyed by canonical target plus recorded/current revision. A stale generation must be discarded by the existing hydration generation guard.
5. Add a pure presentation DTO in `crates/kuzushi-tui/src/ui_view_models/journey.rs`, for example `CheckpointDrift { phase, recorded_revision, current_revision, dirty_changed, relationship }`. Build it from the most recent same-target selected checkpoint only when the exact current checkpoint is absent. Carry it into `EngagementHeaderModel` in `ui_view_models/phase_cockpit/mod.rs`.
6. Render one warning line before the generic reality atom in `crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/header.rs`:

   - ancestor: `accepted Map is stale · rev abc1234 → def5678 · 3 commits behind · rerun Map`
   - dirty-only: `accepted Map is stale · working tree changed since acceptance · rerun Map`
   - diverged/unavailable: `accepted Map is stale · revision changed abc1234 → def5678 · distance unavailable · rerun Map`

   At narrow widths, preserve `Map stale`, both short revisions when present, and `rerun Map`; truncate commit-distance prose first.
7. Use this durable checkpoint comparison as the relaunch staleness signal. Keep the live `workspace:stale` watcher chip (`crates/kuzushi-tui/src/ui_view_models/status_footer.rs:126-127`) for changes observed during the current process, but do not depend on it for changes made while Kuzushi was closed. Clear the drift warning only after a selected checkpoint exists for the exact current snapshot.

### Focused regression tests

- `crates/kuzushi-core/src/workflow_attempts/tests.rs`: a selected old-revision Map is returned by the target-identity history query but not by `selected_for`; a different target and an unselected attempt are never returned.
- `crates/kuzushi-core/src/workspace/git_metadata.rs` tests with a temporary repository: ancestor returns `AheadBy(1)`; sibling branches return `Diverged`; missing recorded object returns `RecordedRevisionUnavailable`; same SHA plus dirty transition stays `Same` with dirty drift.
- Inline tests in `crates/kuzushi-tui/src/ui_view_models/journey.rs`: an old selected Map leaves `current == Map` and produces `CheckpointDrift`; an exact selected Map produces no drift; an old attempt for another target produces no disclosure.
- `crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/header/tests.rs`: wide ancestor, dirty-only, divergent, and narrow renderings include the honest cause and remediation.
- Hydration test in `crates/kuzushi-tui/src/app/view_hydration/completion_tests.rs`: an obsolete comparison generation cannot overwrite a newer target/revision result.

### Change-risk note

Avoid the already-modified broad snapshot files `crates/kuzushi-tui/src/renderer/tests.rs` and `app/tests.rs` where focused module tests can protect the behavior. Existing Map snapshots are also dirty; update them only after a deliberate hand-merge if the final warning changes those fixtures.

## Workstream 2 — announce a crash recovery exactly once

### Re-verification

Supported. Reading recent run summaries can repair a stale `running` record under the store lock (`crates/kuzushi-core/src/run_artifacts/run_summary_store.rs:823-877,995-1032`). The repair writes an interrupted summary, terminal event, and `data.recovered=true` result (`run_summary_store.rs:1053-1062`; `run_artifacts/tool_run_record_events.rs:22-35`). The public recent-entry projection retains only run id, path, and state (`run_summary_store.rs:27-38,366-371`), so the fact that this read performed the transition is lost. Target hydration always requests recent summaries (`crates/kuzushi-tui/src/app/view_hydration/requests.rs:47-58`), but the application step only caches them (`app/view_hydration/mod.rs:313-397`). This explains why the repair is durable and correct yet not announced.

### Proposed change

1. Keep the stored summary/result/event schema unchanged. Do not infer recovery later from every interrupted result carrying `recovered=true`; that would repeat the notice on every launch.
2. Change the internal repair result in `crates/kuzushi-core/src/run_artifacts/run_summary_store.rs` to return both the materialized summary and transition metadata:

   `RecoveredRun { run_id, reason }`, present only when this invocation changed `running` to `interrupted`.

   `load_run_summary` may discard that transient metadata for compatibility. Add a recent-list API such as `list_recent_run_summary_entries_with_recoveries` returning `{ entries, newly_recovered }`; retain the existing list API as an entries-only wrapper if it has non-TUI callers.
3. Carry `newly_recovered` in the run-summary hydration value through `crates/kuzushi-tui/src/app/view_hydration/{reader.rs,value.rs}`. In `ShellApp::apply_view_hydration_drain` (`app/view_hydration/mod.rs:313-397`), react only after the result passes the current generation/target checks.
4. Emit one durable transcript line per recovery and one aggregated in-app notice:

   `Recovered 1 abandoned run as interrupted · 9c118a58 · open jobs or replay 9c118a58`

   For multiple runs: `Recovered 3 abandoned runs as interrupted · open jobs`. Use warning tone, not failure or success tone. Do not add a permanent Attention item: transition metadata already guarantees the message appears only to the process that performed the repair, and `jobs` remains the durable inspection surface.
5. Keep `Run Focus` idle when no process is live. The notice describes the historical repair; it must not fabricate a live activity session.

### Focused regression tests

- `crates/kuzushi-core/src/run_artifacts/run_summary_store.rs`: a stale PID/birth-identity record returns one `RecoveredRun` on the repairing read; a second read returns none; summary/result/event remain interrupted and idempotent.
- Same module: a genuinely live identity returns no recovery and remains running; an already interrupted run returns no new recovery.
- `crates/kuzushi-tui/src/app/view_hydration/completion_tests.rs`: current-generation recovery emits the notice and transcript once; a repeated ready value without `newly_recovered` emits nothing; a stale target/generation emits nothing; multiple recoveries aggregate without hiding copyable run refs from `jobs`.

## Follow-on workstreams

These findings are supported, but should follow the two state-transition disclosures above.

### 3. Typed long-running work: warn without calling it stalled

`activity_observability.rs:35-78` treats an open model call as `Live` at any age, and its tests explicitly hold that at 400 seconds (`crates/kuzushi-tui/src/ui_view_models/activity_observability.rs:304-325`). `ActivitySession` times only `ModelCallStarted/Finished` (`app/view_state/activity.rs:153-219,614-659`) although lifecycle events also include `ToolCallStarted`, `ToolCallProgress`, and `ToolCallFinished` (`crates/kuzushi-core/src/run_lifecycle/domain/item.rs:244-277`).

Generalize activity timing to an `OpenCallTiming` for model and tool calls, with `started_at` and `last_signal_at`. Keep the 30-second signal boundary, but add a presentation-only long-quiet boundary (proposed 120 seconds): before it, a typed call remains `Live`; after it, render warning tone as `LONG MODEL CALL` or `LONG TOOL CALL`, elapsed/quiet age, cost pending where applicable, and `Ctrl+C cancels`. Never label a typed deterministic tool `NO PROGRESS SIGNAL`, never auto-cancel it, and never switch provider/model. A tool progress event resets quiet age but not elapsed age.

Tests belong beside `activity_observability.rs`: model at 45s is Live; model at 400s is Warning but not failed/stalled; quiet tool work names the tool rather than `NO PROGRESS SIGNAL`; progress resets quiet age; finish clears timing; duplicate starts preserve the original start.

### 4. Completion notifications for ad-hoc runs and visible focus blindness

`AttentionBroker` creates completion items only from phase-attempt results (`crates/kuzushi-tui/src/app/attention.rs:159-175`). `attention_notify.rs:9-43` deliberately skips notifications when focus is unknown, and `app/runtime/refresh_terminal_redraw_state.rs:19-51` discards the structured skip reason. The general completion path does publish a `RunFocusReceipt` for every run (`app/background_events/drain_background_events/runtime_event_drains.rs:186-257`; receipt fields in `app/view_state/activity.rs:263-278`).

Add a transient, notification-only completion queue populated when a run receipt is published. The terminal loop consumes each stable run-ref id once. Phase-result completions retain their existing `RESULT READY` signal and must be deduplicated against the transient receipt; ad-hoc completions get `RUN COMPLETED`, `RUN FAILED`, `RUN CANCELED`, or `RUN INTERRUPTED` based on terminal truth. Do not add ad-hoc receipts to the persistent Attention footer.

When `ui.notify=true` and focus is `Unknown`, add a status-footer segment in `ui_view_models/status_footer.rs`: `notify unavailable · terminal focus unknown`. Log at most one warning when a pending completion is skipped. Remove the segment once the terminal reports focus. Keep the fail-closed notification policy.

Focused tests: pure notification-batch tests for one ad-hoc signal, phase deduplication, and terminal outcomes; `status_footer/tests.rs` for unknown/blurred/focused states; runtime test that `FocusUnknown` logs once and never sends.

The audit's Terminal.app-specific claim is not established by this code read and should be rejected as written. The supported claim is only that a terminal which has not reported focus is fail-closed and the skip is invisible.

### 5. Make full decision history visible

The persistence reader returns every decision (`crates/kuzushi-core/src/findings/persistence/open/review_decisions.rs:46-68,95-110`) and the TUI cache retains them (`crates/kuzushi-tui/src/app/domain_cache.rs:672-679`). `FindingDetailModel` reduces them to a one-line latest-decision summary (`crates/kuzushi-tui/src/ui_view_models/findings.rs:113-165,408-437,1897-1950`), which `renderer/views/workbench/detail_pane.rs:260-316` renders.

Add `DecisionHistoryRow` plus a bounded newest-first list and overflow count to `FindingDetailModel`. Extract a shared pure identity matcher from `ui_view_models/review_state.rs:104-219`; when a durable finding identity exists, never mix records that match only the legacy display id. Render verdict, timestamp, actor/author, and wrapped rationale, with the current decision first. Tests in `ui_view_models/tests/review_queue.rs` should cover multiple decisions, durable-identity isolation, ordering, and overflow; detail-pane tests should prove an older rationale and timestamp are readable.

Avoid modifying the already-dirty `app/findings/show_aliases/refresh_findings.rs`; the records are already loaded.

### 6. Persist the operator's autonomy preference globally, then clamp it per target

`V2Config.autonomy` is `serde(skip)` and defaults to `Fix` (`crates/kuzushi-core/src/config/config_model.rs:14-23`); TUI changes are memory-only (`crates/kuzushi-tui/src/app/autonomy.rs:14-91`). Preserve the serde skip so a target config cannot steer autonomy and headless callers keep their current default.

Store a shell preference under a global-only option-store key such as `ui.autonomy`. Add `preferred_autonomy` to session state; startup reads only `OptionScope::Global`, while applied autonomy is `preferred.capped_by(phases.stop_after)`. Chords/verbs update and save the global preference; a failed save says `applied for this session; not saved`. Target changes recompute from the preferred rung, preventing a restrictive target from permanently lowering the preference. Ignore workspace/session values for this key. Update `docs/operator-control-surfaces.md`, which currently describes the dial as session-scoped.

Tests in `app/autonomy.rs`: global round-trip; absent value defaults to Fix; workspace value cannot steer; cap clamps applied posture without changing preferred posture; returning to an uncapped target restores preferred; failed persistence is explicit.

### 7. Disclose volatile steer, budget, and draft state before exit

Session state owns the steer queue and edited session budget (`crates/kuzushi-tui/src/app/session_state.rs:27-33,225-230`); Setup writes only the in-memory budget (`app/state_transitions/picker_keys.rs:235-270`). The quit-confirm model lists active work only (`ui_view_models/quit_confirm.rs:38-135`), and idle Ctrl+C exits directly (`app/state_transitions/exit_requests.rs:218-230`).

Add a pure `VolatileSessionSummary`: queued steer count; whether the session budget differs from saved configuration; composer draft presence/length; and active route/editor draft categories. Never include credential draft content. Add a `NOT SAVED` section to quit confirmation. If no jobs are live but this summary is non-empty, idle Ctrl+C opens quit confirmation; it exits immediately only when both live work and volatile state are absent. Explicitly say the listed state will be discarded.

Tests in `ui_view_models/quit_confirm.rs`: queue, budget, and draft rows; credential redaction; empty state unchanged. A focused `exit_requests.rs` test proves idle-with-draft confirms and idle-empty exits. Automatic persistence of budgets and arbitrary drafts is deferred: the budget is expressly session-scoped, and drafts may contain credentials or other sensitive text.

### 8. Show option/config sources and remove the fictional $5 budget

`ui_view_models/cost.rs:4,41-67,176-180` substitutes `$5` when no session budget exists. This conflicts with the Setup contract that unset means not enforced. Remove `DEFAULT_SESSION_BUDGET_USD`; represent the budget bar as optional. With no budget, show amount spent and `budget · not enforced`, no percentage. Show `spend_hard_ceiling_usd` separately as a configuration validation ceiling, never as the live spend denominator.

The option store already knows effective scope (`crates/kuzushi-core/src/options/option_store_effective_input.rs:93-126`), but `ui_view_models/options.rs:88-99,201-215` omits it. Generalize the core query to return `StoredOptionOrigin { scope, target, stored_key }` using the exact same precedence loop as effective merging, including aliases. Add a `SOURCE` column such as `session/tool`, `workspace/module`, or `global/all`.

Expand the in-shell config projection (`ui_view_models/config.rs:154-177`) with a `CONTROLS` section: effective session budget and source, hard ceiling, stop-after, preferred/applied autonomy and source, notification/auto-open UI toggles and their option origins, plus global/workspace option-store paths. Add a bounded `STORED DEFAULTS` list keyed by scope and target.

Do not promise safe display of every stored value yet: `OptionSpec` has no secret/sensitive marker (`crates/kuzushi-descriptor/src/descriptor_model.rs:170-199`). Show stored keys and origins now, and show values only for explicitly non-sensitive descriptor types/keys. Adding a `sensitive` descriptor contract plus migration is a separate module-contract change. Thus the audit demand for unconditionally displaying *all* `setg` values is deferred, not silently approximated.

Focused tests: `ui_view_models/cost/tests.rs` proves unset never contains `$5`, configured budget computes a percentage, and hard ceiling is independent; core option tests prove origin precedence and alias resolution; `ui_view_models/options/tests.rs` proves source labels; `ui_view_models/config/tests.rs` proves the new control rows and redaction. The config tests file is already dirty and will require a hand-merge.

### 9. Clear session tool options on a real target switch

Supported. `app/session/handle_context_command/navigation_target_story.rs:155-176` explicitly merges `OptionScope::Session` into the next target's option store. The existing test at `app/tests.rs:12878-12911` codifies that behavior. In contrast, reloading external options for the same target (`navigation_target_story.rs:265-282`) should preserve session values.

On canonical target identity change, do not merge the previous target's session bindings. Clear them and say `cleared N session option(s) from the previous target; use setg for cross-target defaults`. Initial activation and same-target reactivation do not warn; same-target external reload preserves session values. Update the options help text to call session values `current-target and current-session` values.

Replace the cross-target-preservation test with a clearing test, add a same-target-preservation case, and retain the external-reload test. `app/tests.rs` is already modified, so implementation must hand-merge rather than overwrite it.

## Explicit deferrals and rejections

- Reject weakening exact revision/dirty checkpoint equality. It would turn stale evidence into current progress.
- Reject a universal numeric commit distance. Show it only after a proved ancestor relationship; otherwise say `diverged` or `distance unavailable`.
- Reject inferring a fresh crash recovery from persisted `recovered=true` on every launch. Announce only the read that performed the transition.
- Reject an automatic timeout/cancel/provider fallback for a long model call. This pass improves observability only; the existing execution watchdog remains authoritative.
- Reject the terminal-brand assertion. The code supports `focus unknown`, not a claim about every version/configuration of a named terminal.
- Defer persistence of arbitrary drafts and session budgets; disclose their loss first, and never persist credential drafts implicitly.
- Defer unredacted display of all stored option values until the descriptor contract can identify sensitive inputs.

## Suggested landing order

1. Core selected-checkpoint history query + async revision relationship; journey/header disclosure.
2. Core recovery-transition metadata + hydration notice.
3. Typed long-call observability and ad-hoc/focus notification disclosure.
4. Decision history, autonomy preference, volatile-exit summary.
5. Cost/config/options provenance and target-scoped session options.

Run the narrow module tests after each item, then `pnpm quality:crap-risk` for changed production Rust and `pnpm verify:quick:summary` once the batch is assembled. Do not regenerate broad snapshots until focused behavior tests pass and the existing dirty snapshot changes have been reconciled.
