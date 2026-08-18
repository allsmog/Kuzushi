# Experience hardening — input, commands, transitions, cancellation, and empty states

Stage 1 proposal only · 2026-08-18 · production and test source were read, not edited

## Decision summary

The critical failure is real and has one root cause: picker views capture every printable key before the composer. Only `:` moves focus to the prompt; other letters are interpreted as picker shortcuts or swallowed. This can drop a leading `q`, execute `s`, or move on `j/k`. Fix that contract first. It also resolves the reported `demo`, `scene`, and `activity` failures, whose downstream routes already work.

Accept four implementation groups, in order:

1. Make the composer live and lossless in every picker-owned view; normalize demo guidance; stop logging mode flips.
2. Preserve finding identity across Review → Prove and make proof deferral durable on the Prove surface.
3. Add honest expert verbs for diff-scoped scanning and exact repeat; make one-off false-positive dismissal require the operator's reason.
4. Refresh terminal receipts from the final cost state.

Reject restoring a one-letter `d` demo shortcut, changing idle `Ctrl+C` in this campaign, adding separate `scene` or `activity` behavior, and changing focused-module option routing. Reasons and protective tests are below.

The worktree was already dirty. In particular, `app/tests.rs` and `state_transitions/view_hotkey_actions.rs` have unrelated edits. Implementers must preserve them and put new tests in the nearest module-local test file where possible.

## Group 1 — one input contract for picker-owned views (critical)

### Production change

- In `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:23-108`, replace the colon-only entry rule with printable-command takeover:
  - editor-specific owners (file picker, credentials, option editor) keep first refusal;
  - when a picker list owns focus, any unmodified printable character moves focus to `PickerFocus::Prompt` and inserts that exact character;
  - `:` remains a compatibility prefix: it focuses the prompt but is not inserted;
  - list operation remains on arrows, Enter, Esc, PageUp/PageDown, and explicit modified chords; remove plain `j/k/q/s/d` picker actions from the list-focus path so a command's first character can never navigate, quit, start, or disappear;
  - `handle_picker_control_or_swallow` may still swallow unsupported non-printable keys, but never printable text.
- In `crates/kuzushi-tui/src/app/state_transitions/text_input.rs:59-88`, route paste through the same ownership rule. A paste on a picker list focuses the prompt and inserts the complete normalized string. The API-key editor remains the only credential paste owner. Do not let Navigate mode discard picker command paste.
- Update picker key labels in `crates/kuzushi-tui/src/renderer/views/onboarding/target_picker.rs`, `model_picker.rs`, and the Setup/planning picker footers to advertise arrows/Enter/Esc and “type a command”; do not advertise removed letter shortcuts.
- Normalize the offline route to bare `demo` in those renderer files and in the defer notices at `crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:481,493,674`. `:demo` remains accepted, but it is no longer required.
- In `crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:1401-1421`, remove the two successful mode-transition calls to durable `self.log`. The mode is already visible in composer chrome. Keep the refusal log when a non-empty prompt prevents Navigate mode.

This deliberately chooses “printable means command” over ambiguous single-letter navigation. The current split contract cannot preserve both `q` as quit and `queue …` as lossless text without a timeout or hidden heuristic.

### Regression tests

Add module-local tests in `state_transitions/picker_keys.rs` / `picker_keys/tests.rs` and `state_transitions/text_input/tests.rs`:

- From TargetPicker, Setup, and PlanningPicker, type `demo`, `queue run secret-scan:scan {}`, `scene`, `activity`, and `proof defer F-0001 --reason later`; assert the composer contains the byte-for-byte string before Enter. The first `q`, `s`, `j`, and `k` must not invoke picker actions.
- Enter submits the same parsed command/effect from each view. `demo` must produce `StartOfflineDemoFixtureScan` without a colon.
- `:demo` still works and does not leave `:` in the submitted line.
- Pasting the queue command retains its full first word. Credential and budget editors still own their input.
- Arrow/Enter list selection, Esc behavior, and global Ctrl/Alt chords remain intact.
- Toggle Prompt ↔ Navigate ten times; assert mode changes but transcript/log length does not. The blocked transition with non-empty input still emits its corrective line.
- Renderer snapshots assert every demo hint names an accepted route and none claim a `d` shortcut.

### Findings closed by this group

- Critical input inconsistency: direct fix.
- Critical demo route: direct fix; no extra route required.
- Mode-flip transcript noise: direct fix.
- `scene` empty and `activity` reopen: command delivery fix plus end-to-end regressions, described under “already-correct routes” below.

## Group 2 — identity-safe transitions and visible proof deferrals

### Review → Prove identity

The defect is confirmed at `crates/kuzushi-tui/src/app/state_transitions/view_hotkey_actions.rs:310-319`: `open_review_queue_finding` changes to Prove before resolving the cursor, so the numeric cursor is interpreted against a different projection.

Change it to capture the Review-visible finding's stable identity first, then transition:

- Resolve the current row once while `WorkbenchPage::Review` is active.
- Pin/open that finding using its stable fingerprint/alias via a small identity-taking helper beside `crates/kuzushi-tui/src/app/findings/show_aliases/open_cursor.rs:4-16`.
- Only after selection succeeds, call `set_workbench_page(WorkbenchPage::Prove)` and focus Prove detail. Never resolve the cursor again after the page change.

Regression test in a module-local `view_hotkey_actions` test module: create a Review order where cursor 1 is finding B while the Prove projection at cursor 1 is finding C; press Enter and assert `selected_finding` and the Prove heading remain B. Also cover an empty row and a locked Prove page.

### Deferred proof receipt

The ledger persists full deferral data (`crates/kuzushi-core/src/workflow_attempts/domain.rs:249-278`) but exposes only a boolean (`workflow_attempts/ledger.rs:137`). The Prove DTO (`crates/kuzushi-tui/src/ui_view_models/phase_cockpit/mod.rs:240`) cannot render the reason.

- Add `PhaseAttemptLedger::proof_deferral_for(...) -> Option<&ProofDeferralRecorded>` beside `proof_is_deferred_for`; make the boolean delegate to it. Matching must retain the current fingerprint/identity/scan-generation rules.
- Add an engagement accessor in `crates/kuzushi-tui/src/app/view_state/engagement.rs:173-190` and a small `ProofDeferralModel { reason, actor, recorded_at, scan_id }` field on `ProvePhaseModel`.
- Populate it in `ui_view_models/phase_cockpit/confirm.rs:10-38`.
- In `renderer/views/workbench/phase_pages/confirm.rs`, render a `PROOF DEFERRED` receipt immediately after STATUS/NEXT, including the operator's reason and generation. A deferral is not proof and must not use proof-success styling.

Tests:

- Core ledger: current-generation lookup returns the exact record; stale scan id and changed identity do not.
- View model: reason/actor/time survive projection.
- Off-screen wide and narrow renderer tests: `PROOF DEFERRED` and the reason remain visible; no blank body; no “verified” implication.

## Group 3 — honest expert verbs and one FP path

### Diff-scoped rescan

The audit is correct: `since <ref>` at `app/command_router/command_effects.rs:404` filters persisted findings; it does not run a scan. Keep filtering but name it honestly.

- Add canonical `findings since <ref>` for the existing filter. Retain bare `since <ref>` as a compatibility alias that emits one notice: “filtered saved findings only; use `scan since <ref>` to run.” Update `commands/argument_commands`, `commands/label.rs`, and `commands/shell_command_specs/findings_evidence.rs`.
- Add `scan since <ref> [--include-worktree]` as a distinct command/effect. At the effect/runtime edge, call the existing core `git_diff_files`, then dispatch `sast:scan` through the normal registry preparation path with canonical `paths` and `diffBase` input.
- If the diff is empty, do not dispatch: say “0 changed files; no scan started.” This guard is mandatory because an empty `paths` value must never widen silently to a full-repository scan. Invalid refs are explicit errors. Default `include_worktree` to false to match CLI scan behavior.

Tests in `commands/tests.rs` plus a focused effect-runtime test: parser distinction; exact changed paths in a temporary git fixture; prepared input contains `paths` and `diffBase`; empty/invalid refs dispatch nothing; legacy `since` still only changes the finding filter.

### Repeat/retry

Do not alias this to `resume`: resume requires resumable checkpoints and has continuation semantics. Add `repeat` (aliases `retry`, `rerun`) for the latest terminal tool invocation on the current target.

- Extend command label/parser/spec files.
- Extract the existing rerun-review construction at `app/state_transitions/key_dispatch.rs:588,1492` into a small application helper that reads the recorded tool and canonical `input.json`, revalidates it through normal prepared-tool dispatch, and opens the existing review modal. Enter confirms spend; the verb never auto-runs.
- Accept completed, failed, interrupted, and canceled terminal runs. Refuse running runs, missing/corrupt input, and target mismatch explicitly.

Tests: canceled run without a checkpoint can be repeated; completed run can be repeated; both open review with exact tool/input and create a new run only after Enter; running/missing-input cases dispatch nothing. Existing `resume` tests remain unchanged.

### False-positive actions

Do not collapse suppression into dismissal: a suppression is a durable matching rule, while dismissal is a one-finding review decision. Instead, make the primary one-off route consistent and honest:

- Canonical one-off FP remains `dismiss false_positive <note>` using the structured `DismissReason` path.
- Change backlog `f` in `state_transitions/view_keybinding_groups.rs:462-470` and `view_hotkey_actions.rs:730-751` to draft `dismiss false_positive ` for the selected finding rather than immediately persisting a fabricated generic rationale.
- Keep `decision rejected_false_positive …` as a compatibility command, but remove it from primary help/examples and point to `dismiss`.
- Label `x` as “create suppression rule”; keep its required `--reason` and expiry semantics visibly distinct.

Tests: `f` writes no decision before submission and drafts the exact structured route; submitted note persists `FalsePositive` plus the operator text; `x` still creates a rule; compatibility decision parsing remains.

## Group 4 — one final cost state

`ActivitySession::mark_run_focus_terminal_pending` snapshots receipt cost at `app/view_state/activity.rs:452-470`. Later cost settlement can update `runtime_cost_report`, so the header at `ui_view_models/activity_header.rs:96` and the receipt can disagree.

- Extract one formatter for `RuntimeCostReport` and use it for both header and receipt states (exact zero/no model calls, incomplete lower bound, unavailable, accounting error).
- In `app/background_events/drain_background_events/runtime_event_drains.rs:240-259`, immediately before publishing/persisting the receipt, refresh `receipt.cost` from the activity session's final `runtime_cost_report`. Do not treat `$0` as “not recorded” when runtime policy proves no provider call occurred.

Regression tests beside `runtime_event_drains.rs`: create the receipt while accounting is unavailable, settle to exact zero before finalization, and assert header + heartbeat/receipt agree. Repeat for incomplete and accounting-error states. No rendered frame may contain both `$0.0000` and “cost not recorded” for the same session.

## Already-correct routes: test, do not redesign

### `scene` on an artifact-less target

No independent empty-state bug remains in the route. `app/command_router/handle_scene_command.rs:24-45,199-254` opens DFD as the permanent empty-capable page; `ui_view_models/viz_data/dfd.rs:121-145` supplies an empty hint; `renderer/views/scene/diagram/dfd.rs:138-145` renders “no data-flow diagram” and guidance. The live failure was the swallowed `scene` command.

Add one end-to-end regression after Group 1: type `scene` from Setup list focus, submit, assert Scene/Dfd opens and off-screen output contains the empty CTA. Reject a second notice or dummy deck.

### Reopening a terminal activity

`ShellCommand::Activity` already passes the current run id (`app/command_router/command_effects.rs:436-438`), and `open_activity_effect` (`app/effects.rs:1011-1019`) preserves an existing terminal `ActivitySession`. The live `activity` command was swallowed on Setup.

Add one regression after Group 1: install a canceled terminal session, type `activity` from Setup, submit, and assert the same run id and canceled rows render. Do not create a new manual session or add a persistence layer in this campaign.

### `use X; set OPT v; run .`

Current source already routes implicit `set` to the focused module's primary tool: `app/options/show_options/option_resolution.rs:5-26`; the writer targets `OptionScope::Tool` in `option_updates.rs:4-48,285-320`; `run .` resolves the same focus in `tool_runner/run_tool/tool_resolution.rs`. Reject a production rewrite.

Add the missing sequence test: execute `use <module>`, then a real `set <declared-option> <value>`, then `run .`; assert the option-store key and dispatched prepared input both target that module's primary tool. This is stronger than the existing test that seeds the option store directly.

## Rejected/deferred

- **Restore picker `d` for demo — reject.** It recreates the same printable-key collision and is unnecessary once bare `demo` works everywhere.
- **Two-step/confirm idle-picker `Ctrl+C` — defer pending an explicit operator-contract change.** `AGENTS.md` ratifies immediate idle `Ctrl+C`/`Ctrl+D` exit and cancel-while-active semantics. This campaign should not silently contradict that contract. Group 1 removes the failed-demo trigger that caused confused cancellation. Update picker footer copy to disclose `Ctrl+C exits`, and retain tests for the three existing states: idle exits; active requests cancellation without exit; cancellation-pending waits safely. If product owners choose a confirm policy, amend the contract first and apply it consistently to Ctrl+C/Ctrl+D, not picker-only.
- **Make `retry` silently resume — reject.** Resume and exact repeat have different truth conditions; conflating them would hide whether execution continues a checkpoint or starts over.
- **Unify suppress and dismiss storage — reject.** Their scopes are intentionally different. Unify the language and reason capture, not the domain records.
- **New Scene or Activity empty-state implementation — reject.** Both downstream surfaces exist; the input-layer regression prevented reaching them.

## Verification gate for implementation

Run the narrow module tests for each group first, then `pnpm quality:crap-risk` for changed Rust production code, then `pnpm verify:quick:summary`. Finally rerun the previously blocked journeys J8, J9, J12, J42, J50, J51, and J52 sequentially. The hard acceptance invariant is: every typed or pasted command is either reproduced exactly in the composer and submitted, or rejected with an explicit reason; no picker may consume a printable prefix as navigation or action.
