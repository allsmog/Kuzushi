# Direct scanner source settlement and artifact receipts

Two prepared-dispatch regressions reproduced direct-scanner inconsistencies.
License scans saved canonical observation snapshots but declared no artifact
delta in their Scan receipts. Semgrep returned partial after a source change,
but its earlier finding commit left the ledger run completed. Both empty and
nonempty Semgrep results reproduced the status mismatch.

## Changes

Direct Semgrep now separates analysis, final source verification and persistence.
The final completed/partial outcome controls the observation commit. Partial
observations retain the original source identity, measured finding delta and
persisted run reference through reopening. The existing source-bound error path
also wraps settlement failures. Static-evidence indexing, normalized findings,
inspection receipts, descriptor options and ordinary output remain compatible.
License and Semgrep use the same completed/partial status conversion.

License publication writes its canonical `findings.json` first, then records that
successful publication in `scan.artifactDelta`. Empty snapshots are explicit
artifacts too. The field uses the existing run-relative path convention, and
the phase receipt does not list itself. Phase metadata construction is separate
from Scan data construction. Existing schemas, public tool ids, options and
historical receipt bytes remain.

## Verification

Evidence root: `/tmp/kuzushi-direct-scan-settlement-20261016`.
`regression-before.json` records the corrected red cases. Two license tests fail
because saved observations are absent from the artifact delta. Two Semgrep tests
fail because a partial result leaves a completed ledger run. The initial test
receipt-access mistake is retained under `before-fixture-fix`; its compilation
failure is not product evidence. The same seven targeted checks pass after the
fixes in `regression-after.json`.

Final focused validation has 170 distinct Rust passes: 117 Core and 53 TUI. It
covers source settlement, late cancellation, native partial/stopped work,
completed coverage reconciliation, license policy, exact scope and context,
direct Semgrep persistence, its static-evidence compatibility, comparisons,
Scan and Report readers. The workspace build passes. The risk proxy passes for
144 changed code files and its 15 support checks.

All ten repository summary gates pass. The receipt is dirty, reports
`driftedDuringRun: true` and is unsigned. It is development evidence, not
clean-commit or release verification. Final evidence documentation is checked
separately after this update.

Native J297 runs installed Semgrep with an owned local rule matching a labeled
inert marker. It retains one observation and a scripted deferral, changes source
during a later empty scan, and checks partial result and ledger status. Review
keeps the original decision at six sizes. Hydrated Report shows partial work
awaiting disposition, an unrecorded revision and explicit coverage limitations.
A separately requested stable empty run does not close the earlier finding.
No-color restart preserves two completed runs, one partial run, one observation
and one decision. It has 20 machine passes, zero failures, 17 capture pairs and
five pending human judgments.

Native J295 repeats enabled-rule, disabled-rule and covered-absence comparisons
with actual local license inspection. Its helper checks the canonical snapshot
against every receipt's artifact delta, including both empty runs. Six sizes,
actual narrow paging, retained decisions and no-color recovery remain. It has
27 machine passes, zero failures, 22 capture pairs and four pending human
judgments.

Final native SHA-256:
`037ea068612624b4628cea875d95d3a5307c27c1dc64b8c1cdf96fc5562851b6`.
The manifests freeze 13 programs, 4,275 source inputs and 724 runtime inputs.
Final cases are `native/J297/20261016-020209/J297` and
`native/J295/20261016-020310/J295`. Every requested/actual capture size, paired
text/ANSI hash and native identity is checked in `native-evidence-final.json`.
Source/runtime inputs stayed unchanged during both cases. Recovery ANSI also
passes an explicit no-color check. Selected terminal-cell replays were inspected
for compact Review, partial Report, retained decisions and rule-aware absence.
These are ANSI renderings, not OS screenshots, and do not close human judgments.

## Limits

Owned fixture source is inert and never executed. Native Semgrep uses installed
analysis with explicit local rules; the Rust source-change cases use labeled
protocol observations and planned inert edits. Decisions use scripted controls,
not operator UX acceptance or vulnerability validation. Both native cases make
zero live provider requests. Fourteen earlier experiment requests remain spent;
no new allowance is approved.

This qualifies direct Semgrep status settlement and license observation-artifact
reporting for the named cases. It does not prove source-race safety for every
direct adapter, atomic source/persistence transactions, every storage-failure
timing, Git SHA transitions, default scanner usefulness or complete repository
coverage. Direct repetitions here are separate advanced actions, not a finite
campaign acceptance test. Other adapters and the original broad investigation
requirements remain open. No maturity promotion, retirement, reference-level
UX claim or broad delivery checkbox follows.
