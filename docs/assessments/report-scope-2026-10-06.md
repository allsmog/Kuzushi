# Accepted scope in study reports (2026-10-06)

## What changed

A study planned from an accepted scan scope now carries that boundary into its
investigation receipt. When the frozen plan input contains `scanScopeRef`, the
report service loads the exact accepted proposal revision and embeds it as
`scope.acceptedScopeProposal`. The scope object also keeps `scope`,
`scopeFile`, `since` and `scanScopeRef` from the frozen input. These are
additive keys; the receipt stays at schema version 1.

The report reads the proposal as recorded. It does not require current source
to match the source on which the boundary was accepted, so a historical report
keeps the original boundary after files change. It does require the proposal
to be accepted and the selected scope to have discovery members. Missing or
damaged scope evidence fails the receipt before any export file is written, so
a previous good export is never replaced.

The TUI Report shows the boundary name, planned discovery file count, included
paths, proposal coverage totals and whether the inventory was limited, and
states that accepted membership is the planned boundary rather than completed
scanner coverage. Provenance details add the rationale, exact scope reference,
source tree hash, operator exclusions and coverage limitations. A receipt whose
proposal is missing, mismatched or unaccepted is shown as unavailable rather
than as an accepted boundary.

Code:

- `crates/kuzushi-core/src/workspace/application/investigation_report/scope.rs`
- `crates/kuzushi-tui/src/ui_view_models/report_investigation/scope.rs`

## Verification

Focused checks, run one at a time:

| Command | Result |
|---|---|
| `cargo test -p kuzushi-core --lib investigation_report::tests::scope --locked` | 3 passed (red run before the implementation: 2 failed) |
| `cargo test -p kuzushi-core --lib investigation_report --locked` | 6 passed |
| `cargo test -p kuzushi-core --lib export_investigation_receipt --locked` | 1 passed |
| `cargo test -p kuzushi-core --lib workspace_tools --locked` | 5 passed |
| `cargo test -p kuzushi-core --lib export_workspace_findings --locked` | 3 passed |
| `cargo test -p kuzushi-cli --locked export` | 14 + 2 passed |
| `cargo test -p kuzushi-tui --lib report_investigation --locked` | 10 passed (7 new scope tests) |
| `cargo test -p kuzushi-tui --lib report_keys --locked` | 8 passed (damaged-scope export refusal added) |
| `cargo test -p kuzushi-tui --lib report --locked` | 135 passed |
| `cargo test -p kuzushi-tui --lib study_context --locked` | 12 passed |

The core tests run through real `workspace:export-findings` prepared dispatch:
the export retains the selected scope and accepted proposal limits; a report
after source changes embeds the originally accepted proposal; and removed scope
evidence fails with "scope evidence is unavailable" while the previous export
bytes stay unchanged.

Logs are under `.git/bounded-investigations/report-scope-*.log`. Workspace build
and the CRAP-risk proxy (44 changed code files) pass.

## Native journey J95

`/tmp/kuzushi-bounded-investigations-tui/20261006-061350/J95/` with native
binary SHA-256
`88b9bac5c016baaf5f18e0339602dd2bb9eb13bbc143483d435f67613a1fd98a`. Raw result
`REVIEW_REQUIRED`: 48 machine passes, no machine failures. `manual-review.json`
holds seven judgments with text/ANSI hashes and capture provenance: six pass
and one fails.

Host checks confirm one plan whose jobs all carry the accepted `scanScopeRef`,
three completed offline attempts, zero provider reservations, an export whose
embedded and sidecar receipts match and include the exclusion, an identical
proposal after restart, and an unchanged previous export when scope evidence is
missing.

Earlier runs at `20261006-060142`, `-060328`, `-060537`, `-060741`, `-060958`
and `-061149` are kept. Their failures came from the journey script: the format
line sat below the viewport, the wrong export heading was awaited, the
dispatcher's Scan attempt was recorded after the refresh key, and a capture was
taken while Report was still loading.

## Follow-up fixes (same day)

The first J95 review left three findings. All three are fixed.

1. **Source change hid the earlier study from Report.** Report selected only a
   Scan attempt for the current source. `ShellApp::report_scan_attempt` now
   falls back to the latest selected Scan attempt for the target
   (`stale_selected_phase_attempt`, already used for checkpoint drift), unless
   the phase ledger is degraded. Report then shows the study under
   "Recorded on earlier source: current files differ, so this study does not
   describe them." Export stays available; the receipt carries the original
   per-attempt source identities. The journey rail is unchanged and still
   derives Map after drift. The Scan page uses the same history, labeled
   `selected · earlier source`, instead of inferring the newest single run as
   "legacy inferred".
2. **A detached study's Scan attempt was not picked up.** The workspace watcher
   already reported `.kuzushi/v3/workflow/*` writes, but the external state
   handler never reread the phase ledger. It now refreshes the phase-attempt
   projection when either ledger file changes, without moving focus or
   touching the composer draft. Unrelated state artifacts do not trigger it.
3. **Workspace history named one trial.** The displayed Scan line now adds
   `+N more run(s)` for multi-run attempts.

While running the wider suites, `renderer::tests::scan_batch_config_has_tty_and_plain_content_parity`
failed deterministically. Its expectation predates asynchronous usage
history; the committed tree already failed it. The test now hydrates the
usage catalogue through `apply_usage_catalogue` before checking parity.

Evidence: six focused app tests (`app::tests::report_scan_attempt`), two
earlier-source label tests, one multi-run label test, regression suites
`report` (145), `phase_cockpit` (89), `journey` (45), `scan` (365),
`workbench` (245, 3 ignored), `phase_composition_contract` (18),
`plain_parity` (4), `study_context` (12). J95 at
`/tmp/kuzushi-bounded-investigations-tui/20261006-064359/J95/` (native SHA-256
`88002318599d07fbc508872b76fec4731c010c4f48e961e0c1a188535e7e71ff`) records 54
machine passes and nine passing screen judgments. The Scan result card now
appears with no refresh key. The original failing judgment stays in
`20261006-061350`, and `20261006-064157` keeps a journey-script failure (it
expected `workbench` to open Scan after drift).

Remaining observation: the untyped Scan projection counts recorded run
artifacts and engine labels differently from the typed projection (57 vs 16
artifacts, "Run SAST scan" vs "Secret scan"). This predates these changes.

## Limits

Offline `secret-scan` only, over labeled source that is never executed. No
provider requests. Physical contrast, motion, real terminal latency, reference
parity and full investigation acceptance remain open. No delivery milestone is
closed by this checkpoint.
