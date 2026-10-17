# Scan coverage after source verification

An actual prepared-dispatch regression reproduced premature SAST coverage.
When source changed during analysis, the final result was partial but an earlier
completed Scan receipt had already recorded covered absence for a prior finding.
The final source guard could not undo that observation gap.

## Implementation

SAST assembles Scan coverage in memory, then publishes the existing receipt only
after final source verification. A mismatch retains the captured source identity,
marks both run status and Scan coverage partial, and skips completed-scan
reconciliation. Completed engine work remains visible separately. The output
headline agrees with the partial result. Late cancellation refuses publication
and follows the existing stopped-run error path.

Earlier raw observations and human decisions remain. Only a later explicit,
stable scan with qualifying coverage can record absence. Absence does not
establish a fix. Existing prepared dispatch, result paths, schemas, options and
module ids remain; historical receipts are not rewritten. The release notes
document the change in publication timing.

## Verification

Evidence root: `/tmp/kuzushi-scan-source-settlement-20261016`.
The red regression in `regression-before.log` used a labeled synthetic initial
observation and an owned paused scanner-protocol adapter. It failed because the
earlier finding acquired an observation gap after source drift. The corrected
case in `regression-after.log` passes. No target source was executed.

Focused checks have 161 distinct Rust passes: 108 Core and 53 TUI. They cover
source settlement through real prepared dispatch, missing/malformed coverage,
late cancellation, unpublished receipt assembly, completed/partial/stopped
native runs, license policy, context, scope, comparison, Scan and Report readers.
The small subsequent headline correction has four passing targeted checks in
`completion-after-presentation.log`. The workspace build passes; the risk proxy
passes for 141 changed code files and its 15 support checks.

All ten repository summary gates pass. The receipt is dirty, reports
`driftedDuringRun: true` and is unsigned. It is development evidence, not
clean-commit or release verification. Final evidence documentation is checked
separately after this update.

Final J296 uses installed Semgrep with an owned local rule matching an explicitly
labeled inert marker. It records one observation and one scripted deferral,
then changes source during a later empty scan. The finding stays open, with no
observation gap. The hydrated Report shows partial work awaiting disposition,
unrecorded revision and no complete-coverage claim. A separately requested
stable scan then records covered absence while retaining the decision and the
partial run. Six terminal sizes and no-color restart are included. J296 has
26 machine passes, zero failures, 20 capture pairs and five pending human
judgments.

Final J121 checks interrupted work, partial results, protected allowance,
explicit retry/revised allowance, retained decisions and restart through the
ordinary TUI. Its provider transport is intercepted with synthetic fixture
outputs. It is not live-model usefulness evidence. It has 135 machine passes,
zero failures, 100 capture pairs and 17 pending human judgments.

Final native SHA-256:
`ec2710028127c66a0b754696b78bae8056d1cccf58e287ea481362c6420d2ef2`.
The frozen manifests contain 13 programs, 4,274 source inputs and 722 runtime
inputs. Final cases are `native/J296/20261016-013821/J296` and
`native/J121/20261016-013917/J121`. `native-evidence-final.json` checks each
capture's requested/actual dimensions, paired text/ANSI hashes and native
identity. Source and runtime inputs stayed unchanged during both cases.
Selected ANSI replays were inspected for the partial headline, hydrated Report,
40x12 reader and recovery. These are terminal-cell renderings, not OS
screenshots; assistant inspection does not close operator judgments.

The earlier successful native round is retained separately under
`before-partial-output`, with its original timestamped cases. Screen inspection
caught a completed headline despite partial status and a Report captured before
hydration. The headline is corrected, and the final recipe waits for the actual
partial Scan receipt before capturing Report. Earlier evidence is not presented
as verification of that correction.

## Limits

Both final native cases have zero live provider requests and execute no target
source. Fourteen earlier real-provider experiment requests remain spent, with
no new allowance approved. Scripted decisions do not establish operator UX
acceptance or vulnerability validity.

This qualifies shared SAST publication timing on the named cases. Other direct
scanner adapters, every source-race and persistence-fault timing, all rule-policy
parity and complete coverage export remain open. No maturity promotion,
retirement, reference-level UX claim or broad delivery checkbox follows.
