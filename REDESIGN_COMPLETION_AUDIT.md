# Redesign Completion Audit

This audit records current evidence for the defensive-scanner UX/data redesign.
It is not a substitute for full release review; it names what is currently
proved by source inspection and test output.

## Objective Evidence

| Requirement | Current Evidence | Status |
| --- | --- | --- |
| Preserve scanner terminology and reject misleading Fable terms | `ACCEPTED_FABLE_RECOMMENDATIONS.md`, `DOMAIN_RISK_REVIEW.md`, Workbench/detail/export tests naming `severity`, `confidence`, `status`, `decision`, `proof`, `verification` | Proven by docs and focused tests |
| Replace `fixed` wording for run absence | `crates/kuzushi-cli/src/application/runs_diff.rs`; `cargo test -p kuzushi-cli runs_diff -- --nocapture` | Proven |
| Require explicit target for suppression commands | `crates/kuzushi-cli/src/application/suppressions.rs`; `cargo test -p kuzushi-cli suppress -- --nocapture` | Proven |
| Separate machine scanner output from user review state | `ReviewDecision` domain model and append-only store paths; findings tests for user decisions, sticky triage, and no triage mutation | Proven by focused tests |
| Durable identity and line-shift stability | `finding_identity` domain and store tests; `cargo test -p kuzushi-core findings -- --nocapture` | Proven by focused tests |
| Workbench rows/details show distinct severity, confidence, priority, lifecycle, decision, proof, evidence, and verification signals | `crates/kuzushi-tui/src/ui_view_models/findings.rs`, Workbench renderers; `cargo test -p kuzushi-tui findings -- --nocapture`, `cargo test -p kuzushi-tui workbench -- --nocapture` | Proven by focused tests |
| Report preview/export use canonical projection | `crates/kuzushi-core/src/workspace/application/export_projection*.rs`; `cargo test -p kuzushi-core workspace::application -- --nocapture`, `cargo test -p kuzushi-cli export -- --nocapture` | Proven by focused tests |
| Preview and export share serializer/projection path | `previews_single_file_workspace_findings_with_same_body_as_export`; `cargo test -p kuzushi-core workspace::application -- --nocapture` | Proven by focused tests |
| Do not emit misleading `ainalysis` discovery-channel label | `VulnSource::as_str()` emits `analysis`; legacy `ainalysis` remains parse-only; `cargo test -p kuzushi-core vuln_source -- --nocapture`, `cargo test -p kuzushi-cli export -- --nocapture` | Proven |
| File-backed findings migrations record schema version and protect existing DBs | `FindingStore::open` runs a file-backed migration guard; `file_backed_store_records_schema_version`; `file_backed_store_backs_up_legacy_version_before_migration`; `cargo test -p kuzushi-core findings -- --nocapture` | Proven by focused tests |
| Activity uses real trace/run state, terminal summaries, stalled-output warnings, and partial/failure artifact labels | `activity_header_uses_terminal_run_summary_status_and_findings`; `activity_header_uses_partial_run_reason_from_summary`; `activity_feed_pane_rows_warns_when_live_trace_output_stalls`; `activity_deck_labels_partial_run_artifacts`; `activity_view_renders_partial_terminal_outcome_from_run_summary`; `cargo test -p kuzushi-tui activity -- --nocapture`; `cargo test -p kuzushi-tui drain_background_events -- --nocapture` | Proven by focused model, renderer, and event-drain tests |
| Run timeline preserves persisted terminal status meanings | `PastRunStatus::Interrupted` remains distinct from `Failed`; `run_timeline_model_preserves_persisted_terminal_statuses`; `cargo test -p kuzushi-tui run_timeline -- --nocapture` | Proven by TUI view-model and snapshot tests |
| Failed/partial run recovery handoff preserves artifact-review-only semantics | `failure_handoff_model_reads_failed_tool_run_artifact` writes a failed tool run through `record_tool_run_started` + `record_tool_run_failed`, then reads the TUI failure handoff model from the persisted target; `cargo test -p kuzushi-tui failure_handoff -- --nocapture`; `cargo test -p kuzushi-core run_failures -- --nocapture` | Proven by core failure-artifact tests plus TUI selector/render tests |
| No silent model/runtime fallback | `crates/kuzushi-core/src/modules/runtime_requirements.rs`; `cargo test -p kuzushi-core runtime_requirements -- --nocapture`; CRAP-risk refactor preserved input-aware runtime requirements | Proven for shared runtime-requirement helper |
| Run artifact -> review decision -> export report preserves scanner/review separation | `run_review_export_preserves_scanner_output_and_user_review_state`; `run_review_export_uses_real_secret_scan_detector`; `cargo test -p kuzushi-cli run_review_export -- --nocapture`; exported JSON carries `reviewDecision`, `reviewDecisionAuthor`, `triageVerdict`, and run provenance while stored scanner triage remains `None` | Proven by CLI integration tests over persisted run summary, a deterministic real `secret-scan:scan` run, findings DB, review command, and export command |
| Run artifact -> compare -> review preserves durable identity and scanner/review separation | `run_compare_review_records_human_decision_after_diff`; `run_compare_review_uses_real_secret_scan_detector`; `cargo test -p kuzushi-cli run_compare_review`; diff sees durable identities from persisted run artifacts, the public review command records a human decision for the compare run, and the next diff reports stored carry-forward without mutating scanner triage | Proven by CLI integration tests over persisted run summaries, a deterministic real `secret-scan:scan` run, findings DB, run snapshots, diff, and review command |
| Broad workspace regression coverage | `cargo test --workspace --all-targets --quiet`; `cargo fmt --check`; `git diff --check`; `pnpm exec tsc --noEmit`; `pnpm quality:crap-risk` | Proven by final full-suite and quality-gate pass |

## Commands Run In This Audit Pass

- `cargo test -p kuzushi-cli runs_diff -- --nocapture`
- `cargo test -p kuzushi-cli suppress -- --nocapture`
- `cargo test -p kuzushi-tui findings -- --nocapture`
- `cargo test -p kuzushi-tui workbench -- --nocapture`
- `cargo test -p kuzushi-core findings -- --nocapture`
- `cargo test -p kuzushi-core findings::tests:: -- --nocapture`
- `cargo test -p kuzushi-core workspace::application -- --nocapture`
- `cargo test -p kuzushi-core vuln_source -- --nocapture`
- `cargo test -p kuzushi-core export_projection -- --nocapture`
- `cargo test -p kuzushi-cli export -- --nocapture`
- `cargo test -p kuzushi-core runtime_requirements -- --nocapture`
- `cargo test -p kuzushi-tui drain_background_events -- --nocapture`
- `cargo test -p kuzushi-core file_backed_store -- --nocapture`
- `cargo test -p kuzushi-core incremental_index -- --nocapture`
- `cargo test -p kuzushi-core storage_v3 -- --nocapture`
- `cargo test -p kuzushi-core storage_writer_actor -- --nocapture`
- `cargo test -p kuzushi-tui activity_view_renders_partial_terminal_outcome_from_run_summary -- --nocapture`
- `cargo test -p kuzushi-tui activity -- --nocapture`
- `cargo test -p kuzushi-cli decision -- --nocapture`
- `cargo test -p kuzushi-cli run_review_export -- --nocapture`
- `cargo test -p kuzushi-cli run_review_export_uses_real_secret_scan_detector -- --nocapture`
- `cargo test -p kuzushi-cli run_compare_review -- --nocapture`
- `cargo test -p kuzushi-core dispatches_secret_scan`
- `cargo test -p kuzushi-cli run_compare_review`
- `cargo test -p kuzushi-cli run_review_export`
- `cargo test -p kuzushi-tui findings_cursor`
- `cargo test -p kuzushi-core storage_v3`
- `cargo test -p kuzushi-cli runs_diff -- --nocapture`
- `cargo test -p kuzushi-tui failure_handoff_model_reads_failed_tool_run_artifact -- --nocapture`
- `cargo test -p kuzushi-tui failure_handoff -- --nocapture`
- `cargo test -p kuzushi-tui run_timeline_model_preserves_persisted_terminal_statuses -- --nocapture`
- `cargo test -p kuzushi-tui run_timeline -- --nocapture`
- `cargo test -p kuzushi-core run_failures -- --nocapture`
- `cargo test -p kuzushi-core tool_run_failed -- --nocapture`
- `cargo test -p kuzushi-core plugin_sandbox -- --nocapture`
- `cargo test -p kuzushi-core registry_runs_wasm_plugin_and_commits_v3_observation -- --nocapture`
- `cargo test -p kuzushi-tui --test stress --quiet`
- `cargo test -p kuzushi-bdd-tui --test onboarding --quiet`
- `cargo build -p kuzushi-cli --quiet`
- `cargo test -p kuzushi-cli --test cutover_cli --quiet`
- `cargo test -p kuzushi-cli --test dep_hygiene_cli taint_iris --quiet`
- `cargo test -p kuzushi-openai --lib --quiet`
- `cargo test -p kuzushi-core --lib --quiet`
- `cargo test -p kuzushi-tui --test activity_dag_fixture --quiet`
- `KUZUSHI_UPDATE_SNAPSHOTS=1 cargo test -p kuzushi-tui --test snapshots --quiet`
- `cargo test -p kuzushi-tui --test snapshots --quiet`
- `cargo test --workspace --all-targets --quiet`
- `cargo fmt --check`
- `git diff --check`
- `pnpm exec tsc --noEmit`
- `pnpm quality:crap-risk`

## Fixes From This Audit Pass

- Updated stale TUI snapshots for current v3 fingerprint rendering and current
  module/tool counts.
- Changed public discovery-channel output/help from `ainalysis` to `analysis`
  and `analysis-multi`, while keeping the misspelled values as legacy parse
  aliases for stored rows and old filters.
- Refactored `tool_needs_runtime` into input-specific and always-runtime
  helpers so the shared runtime predicate passes the repo CRAP-risk gate
  without changing runtime semantics.
- Applied the narrow `rustfmt`-requested formatting change in the TUI
  background event drain.
- Added a file-backed findings migration guard that checks schema version,
  runs SQLite integrity checks before upgrading an existing DB, creates a
  one-time pre-migration backup, and records the current schema version.
- Split the untracked `incremental_index` module's tests into a sibling
  `tests.rs` file so the dirty worktree passes the CRAP-risk file-length gate
  without changing incremental-index behavior.
- Added render-level Activity coverage proving a partial run summary is visible
  in the Activity screen with partial status, finding count, and failure reason,
  without misleading "clean" wording.
- Added CLI integration coverage for persisted run summary -> human review
  decision -> completed JSON export, including an assertion that user review
  state does not mutate scanner triage output.
- Added CLI integration coverage for a deterministic real `secret-scan:scan`
  run -> human review decision -> completed JSON export, proving real scanner
  output remains separate from user-owned review state.
- Real persisted dep-hygiene and secret-scan outputs now write
  `data.coreFindings` from stored finding rows when a findings store is
  available, so run artifacts carry durable `identityId` and scan provenance
  without changing detector-facing `data.findings`.
- Added CLI integration coverage for a deterministic real `secret-scan:scan`
  run -> run diff -> human review decision -> refreshed run diff, proving
  stored decisions carry forward by durable identity and scanner triage remains
  unmodified.
- Verified the workbench finding-selection cursor path with the existing
  `findings_cursor` keyboard/mouse tests, keeping review navigation state
  separate from persisted scanner findings.
- Split incremental-index language detection and storage-v3 review projection
  into focused sibling modules to keep changed files under the CRAP-risk
  file-length gate without changing projection or indexing behavior.
- Added cross-layer failure/recovery coverage proving the TUI failure handoff
  view model reads a real failed tool-run artifact, keeps proof at
  `artifact-review-only`, preserves forbidden-claim guardrails, and does not
  invent missing-artifact claims when the persisted context says `none`.
- Restored `OptionScope` visibility in the TUI effect type and refreshed the
  failure-handoff snapshot's current top-bar separator so the focused TUI
  failure/recovery tests compile and pass.
- Split the untracked plugin sandbox implementation into policy, snapshot,
  observation, Wasm, and test modules so the dirty worktree passes the
  repo CRAP-risk gate without changing sandbox validation, candidate
  validation, or storage-write behavior.
- Kept persisted `interrupted` run summaries distinct from `failed` in the
  TUI run timeline, styled them as warnings, and added status-vocabulary
  view-model coverage for partial, interrupted, failed, skipped, and paused
  runs.
- Refreshed the run-timeline snapshot's current top-bar separator after the
  focused run-timeline test path surfaced the stale fixture.
- Split the untracked Wasm plugin adapter's output assembly and test fixture
  into focused helpers, moved its test module to a sibling file, and grouped
  plugin prompt dispatch names behind predicate helpers so the repo
  CRAP-risk gate passes without changing plugin dispatch or sandbox behavior.
- Split the storage-v3 writer actor runtime loop/blocking dispatch,
  incremental-index change coalescing, and v3 observation-write assembly into
  focused helpers so the repo CRAP-risk gate passes without changing storage,
  indexing, or scanner-observation semantics.
- Split storage-v3 projection rekey helpers into a focused sibling module so
  the dirty worktree passes the CRAP-risk file-length gate without changing
  rekey safety checks, stale-decision rejection, or projection semantics.
- Updated onboarding BDD fixtures and steps for the current Workbench AIM
  landing surface, Logs transcript workflow, and `RUN`/`REUSE`/`SKIP`
  planning-row vocabulary.
- Fixed the skipped Attach-files planning row so Enter runs the selected phase
  plan instead of opening the file picker; selected Attach still opens the
  picker.
- Updated the saturated transcript stress test to assert public Logs behavior
  instead of the removed raw `logs_scroll` field.
- Aligned CLI cutover coverage with the current hidden `exploit-chain`
  module, `runtime_verified` label, and robust zero-finding demo output.
- Updated legacy `taint-iris:hunt` CLI tests to verify compatibility routing
  into Taint IRIS Next while preserving the legacy input option surface and
  MCP/model precondition semantics.
- Updated OpenAI credential routing tests to enforce the no-silent-provider
  fallback policy when an Anthropic model is requested with only OpenAI
  credentials configured.
- Refreshed Activity verbose-subsystem and broad TUI snapshots for the current
  ellipsized ACTIONS rendering, ASCII top-bar separator, module/tool counts,
  and workspace export help.
- Kept the storage-v3 writer actor dispatch extraction as the single command
  implementation and widened moved helper visibility only to the
  `writer_actor` module boundary for existing unit tests.
- Split storage-v3 finding-observation projection into a focused sibling
  module and kept inventory projectors in their existing submodule so the
  projection code remains under the CRAP-risk file-length gate without
  changing projection semantics.

## Remaining Evidence Gaps

- Existing warnings remain, mostly unused/dead-code warnings in the dirty
  worktree. They do not fail the final full-suite run or quality gates.
- The worktree is large and dirty; human review is still required before
  committing to ensure unrelated changes are intentional.
