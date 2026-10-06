# Native partial coverage, 2026-10-05

This increment repairs the SAST native-engine path when a scanner returns useful
observations alongside reported coverage errors. It remains a partial module
audit on dirty source based on `058388c588333466ca47846322ed38c6733dcabe`.

The aggregate runner previously refused those observations before persisting
them. The Semgrep trait adapter also discarded reported errors. The shared SAST
runner now retains observations, records the native finding run as `partial`,
and writes authenticated `native-coverage.json`. Its version-1 receipt identifies
each engine and selected directory, observation count and original reported
errors. An engine without reported errors retains its separate complete outcome.
That outcome describes execution, not proof of complete source coverage.

The public scalar runner keeps its coverage-error return after retaining the
partial observations. Its `ScanRun` fields are unchanged. Partial scans never
reconcile absent findings as resolved. The findings store can reopen and read
the retained observations and run status. Fatal errors, cancellation and later
static-indexing failure still need the same retention guarantee.

| Operator question | Evidence | Limit |
| --- | --- | --- |
| Can usable discovery survive reported omissions? | Typed-runner tests retain nonempty and empty partial results; prepared SAST dispatch authenticates coverage and reopens findings | Scripted protocol fixtures prove adapter behavior, not engine precision |
| Can an actual installed scanner produce this state? | Installed Semgrep 1.165.0 runs explicit local Python rules, returns one matching observation and an `IncompatibleRule` report for an intentionally unsupported minimum version | Labeled local rule and source, with no useful-default-rule or precision claim |
| Can separate engine outcomes remain distinct? | The same SAST job runs Semgrep and the native secret scanner in `service`; Semgrep is partial while the secret scanner completes without reported errors | This does not certify everything in the directory was inspected |
| Can incomplete absence erase an older finding? | Partial lifecycle regression preserves the prior finding and status after reopen | Source-bound human decisions and other reconciliation paths still need work |
| Can unreadable source become a seemingly complete scan? | Real permission denial blocks source snapshot capture before discovery | No usable permission-gap scan is claimed; privileged processes explicitly skip that denial fixture |
| Can the operator read and accept partial evidence? | J78 has 25 machine passes and 10 separately recorded passing screen judgments across six sizes, Review, Report and no-color restart | This verifies the labeled native fixture, not complete reference interaction parity or a report export |

The original malformed Python, Java, Go and Rust fixtures produced no parser
report with installed Semgrep. Those diagnostics remain in
`.git/bounded-investigations/`. The test does not manufacture a parser failure.
Local rule files avoid remote rule selectors. Metrics are disabled by the adapter,
but the executable may still perform a version check; no live model calls occur.
Descriptor options `semgrepConfig` and `semgrepBinary` apply only to a selected
Semgrep task. Absolute local rule paths avoid scanner-working-directory ambiguity.

The terminal work exposed a result summary that still said completed, an artifact
list that crowded out engine evidence, a five-row clip on guided results and a
long acknowledgement control omitted at common widths. The summary now says
partial, Scan uses a compact receipt and scrollable engine evidence, and narrow
acceptance says `Accept partial` or `Accept` beside the partial result. Guided
failure dialogs retain their space. Paging ranges disclose hidden rows.
Pending-result keymaps retain the same PageUp/PageDown controls, and narrow
receipt columns wrap the partial acknowledgement instead of hiding it. Earlier
failures and separate judgments remain in their original directories; they are
not relabeled as passes.

Final terminal evidence is at
`/tmp/kuzushi-bounded-investigations-tui/20261005-101159/J78/`.
The separate `manual-review.json` records every referenced screen, actual
dimensions, text/ANSI hashes and native binary digest
`7a6613b8a2a564a589c0fc5940b37555e5b5f7767d99ca0591ebb5d08eaa8e41`.
Raw `REVIEW_REQUIRED` remains unchanged. Actual PageDown reaches the remaining
engine rows at 40x12. One scoped native job, its authenticated coverage and the
explicit partial selection survive actual exit and a no-color restart. The
operator rejects the labeled observation as a false positive before opening
Report. This journey does not export a report or start another scan.

Focused core scan checks passed 389 cases. The repaired result, failure-dialog,
phase-cockpit and paging reducers passed their focused checks. The final receipt
wrapping check passed eight Scan renderer tests. Workspace build and the
CRAP-risk gate passed. All ten quick gates passed in
`.git/bounded-investigations/partial-acknowledgement-quick-verification.json`,
finished 2026-10-05T17:13:53.651Z. This is a dirty, drifted working-tree receipt;
it excludes the full CI matrix. Later documentation closeout is separate.

### Standalone native module parity

The follow-up audit found two standalone defects. Semgrep and CodeQL described
reported omissions in their text while returning a completed envelope and
findings lifecycle. They now return and persist `partial` for those omissions.
The shared finding commit retains measured added/updated deltas, including a
measured zero result, and rejects unsupported terminal statuses before writes.
Completed callers keep their existing behavior. Two prepared Semgrep protocol
fixtures prove empty/nonempty partial runs, reopen and measured deltas. A
CodeQL report-adapter fixture proves zero observations with an omission remain
partial. The latter does not execute an installed CodeQL analyzer.

Standalone results also lacked reusable authenticated source identity. The
terminal correctly refused current-source selection. Both executors now reuse
the existing source snapshot guard before discovery and attach its identity to
the result. Existing source-guard tests retain output and spending when source
changes. This is source identity evidence; accepted threat-model inheritance
and source-bound human decisions are still separate requirements.

The terminal next exposed a summary that hid the concrete omission behind
an error count. The shared run receipt now retains up to three bounded omission
previews beside its primary reason, with further omissions disclosed. It
preserves source-verification reasons and original full result messages.
This uses existing cached run summaries rather than filesystem reads in the TUI.

J79 at `/tmp/kuzushi-bounded-investigations-tui/20261005-105209/J79/` records
22 machine passes and nine separate passing screen judgments across all six
sizes, actual 40x12 paging, explicit partial acknowledgement, human review,
Report preview and actual exit/no-color restart. The installed Semgrep runs
one whole-repository job with explicit local rules. Source identity, the partial
finding lifecycle, concrete omission and selection survive restart. No model
calls, remote rule selectors or extra scan jobs are recorded. The native binary
digest is `3ed7e649ee1b95b132afbcd1280507113106d7cbc0fc50cdf0e005c5f5b36b7f`.
Every capture's actual dimensions and text/ANSI hashes are in
`manual-review.json`; raw `REVIEW_REQUIRED` and failed predecessors remain.
The failed recipe incorrectly expected DAG metadata to run a prerequisite,
then guessed unbroken wrapped text and a paging range. Those failures remain
failures. Correcting them does not certify prerequisite execution ordering.

Focused verification passed 88 native-module tests, 389 scan regressions,
the finding commit-status guard, three source-guard tests and nine run-receipt
tests. Workspace build and the CRAP-risk gate passed. All ten quick gates passed
in `.git/bounded-investigations/standalone-native-final-verification.json`,
finished 2026-10-05T17:51:17.743Z. This remains a dirty, drifted working-tree
receipt; documentation closeout and the full CI matrix are separate.

This increment does not promote or retire any module. Standalone scoped target
membership, cancellation, resource limits and complete interface parity still
need dedicated evidence. J79 does not exercise actual CodeQL, useful default
rules, precision, context inheritance or an export. Source drift needs ledger
settlement evidence in addition to the existing output guard. Ad hoc SAST
context binding is not certified by the native fixture: these deterministic
engines do not consume the accepted
threat model. Full provider-context isolation, fatal/cancellation retention,
source-bound decisions, complete coverage export and the full per-tool audit
remain open.

### Native failure, cancellation and later processing

The next audit found the native runner discarding all earlier engine outputs
when a later engine returned an error. It also indexed source before importing
observations, so a later indexing failure lost useful discovery. The runner now
compiles the existing finite engine/scope list once, records each job as complete,
failed, canceled, interrupted or not started, and imports earlier observations
that passed scope checks before indexing. It stops at the first native failure.
Remaining jobs never start, and failed/canceled/interrupted findings runs cannot
reconcile absence. An engine that never returned output has no retained
observation claim.

SAST writes the retained findings, native coverage, measured stage delta and
individual engine outcomes before shared terminal settlement. The authenticated
failed/canceled result retains this evidence and its source identity. The shared
artifact boundary forwards recorded JSON without importing scan execution
policy. Generic tool failures and cancellation retain their previous digest
seeds. Storage failure itself and failures in later delegated engines still need
recovery evidence; the latter can retain native ledger observations without yet
propagating the native receipt through its error.

New native receipts use schema 2. The updated reader accepts schema 1, defaults
its execution disposition to complete and preserves reported omissions. Unknown
versions fail closed. No historical receipt is rewritten. `RELEASING.md` and
`docs/modules.md` describe the migration; public `ScanRun` fields stay unchanged.

The terminal audit found pending guided results swallowing advertised PageDown
keys. Reading now precedes that result question while preserving modal, answer
and other setup-question ownership. Completed, partial, failed and canceled
results page without accepting the attempt or changing its composer draft.
Canceled engines display stopped instead of failed; completed and unstarted
engine outcomes remain distinct. Report history now reuses the cached Scan
projection to show the displayed attempt, source freshness, scope and a bounded
omission preview. It makes no complete repository coverage claim. This is
presentation, not complete coverage export.

J80 at `/tmp/kuzushi-bounded-investigations-tui/20261005-120452/J80/` records
20 machine passes and 12 separate passing screen judgments. Failure reading
covers all six viewport sizes; actual 40x12 PageDown reveals unstarted scope c.
A first failed plan retains one source observation. A separately initiated
second plan is canceled with actual Ctrl+C after the earlier scope returned.
The shell stays open, Report displays stopped coverage and actual exit/no-color
restart restores the canceled receipt and finding. Both durable attempts remain
indexed. Navigation to the older attempt is not exercised by the restart screen.
Each plan has three explicit scopes; only a and b invoke the scanner, with c
never started. Installed Semgrep uses a labeled local rule on a; b is an explicit
failure/cancellation seam. No live model calls or remote rules run. The fixture
is unversioned, so this proves authenticated content identity, not Git SHA
transitions. No human decision or report export occurs in J80.

`manual-review.json` records each actual capture size, text/ANSI hashes and native
binary digest `73378c31a3e4bad115455a5cf931b84fceb36868a42dad9e34e61a75be36a3bc`.
Raw REVIEW_REQUIRED and all failed predecessors remain unchanged. Earlier
attempts separately record incorrect recipe expectations, blank resize captures,
the paging defect and the misleading cancellation label.

Focused verification passed 398 scan regression cases before the final unstarted
scope-detail addition, followed by all five native coverage cases. Shared
prepared observed dispatch proves fatal failure and real cancellation, retained
counts, terminal authentication, source identity and reopen. Lifecycle, generic
terminal digest and malformed recorded-evidence checks passed. The final TUI
checks passed 22 result-key tests, 14 Scan projection tests, three report-receipt
checks and five Report renderer checks. Workspace build and the CRAP-risk proxy
passed. The final quick verification receipt is
`.git/bounded-investigations/native-stop-tui-final-verification.json`; its recorded
result is separate from the terminal judgments and excludes full CI. All ten
quick gates passed at 2026-10-05T19:10:08.628Z. The receipt records a dirty
working tree with its conservative drift flag; it is not a frozen-commit
guarantee.
Documentation closeout is checked separately.

This increment does not establish standalone abort retention, persistence-fault
recovery, later delegated-failure receipt propagation, source-drift ledger
settlement, native resource limits, useful default coverage, accepted model
context or live scan quality. Full coverage export, the remaining per-tool audit,
source-bound decisions and complete reference interaction acceptance remain open.
No maturity promotion or retirement follows from this evidence.
