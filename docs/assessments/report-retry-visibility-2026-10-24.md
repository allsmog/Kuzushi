# Visible Report retry after a refused export

The current full investigation journey stopped during bundle recovery. The
operator had replaced a rejected file destination with a directory, then pressed
Enter while the report receipt was refreshing. The export guard correctly
refused to write from a previous read. When the current read arrived, the body
explained that export had not started and offered a new Enter press. The fixed
destination row still showed only a path, so that result could disappear while
reading or paging.

Report now pins `NOT EXPORTED` beside the destination after a read refusal. It
changes to `RETRY EXPORT` when the current selected report is ready. Both states
remain visible through scrolling and resize. Existing exporting, failed-write
and successful-export states retain their meanings. A completed read never
queues an export; the operator must press Enter again. Plain output uses the same
presentation.

## Verification

The new regression first failed at the missing fixed-row status. All 54 distinct
focused Report checks now pass: fourteen summary/read checks, thirteen keyboard
checks, eight export-worker checks and nineteen rendering checks. The new case
covers refusal before a current read, readiness without an automatic export,
both reader ends at six sizes, plain output, retained draft/cursor and exactly
one export effect after an explicit retry. The workspace builds; TUI all-target
Clippy and the changed-code risk proxy pass. The initial regression exceeded the
function-size limit; its hydration setup was extracted and the focused checks
and Clippy rerun. Final repository summary verification is retained under the
evidence root.

Final sequential J121 records **216 machine passes, zero failures, 130 capture
pairs and twenty pending human judgments**. It runs the complete keyboard journey
from fresh Setup through accepted Map, three fixed Scan jobs, admitted-request
cancellation, explicit attempt revision, a spending stop, partial triage/report,
a specific allowance revision, completed original work, bundle-path recovery,
no-color restart and missing-context recovery. Its thirteen frozen programs and
6,516 source inputs remain unchanged during execution. The executable SHA-256 is
`87c9fe8829fa9dd795c5b83bc49a1b6d9253a331b3acec13508d41e128bf3da8`.

The journey's Report helper allows at most one additional Enter press, only when
the visible fixed row says `RETRY EXPORT`. It does not relaunch model work or
retry indefinitely. The final full run exported on its first attempt, so a
separate owned tmux probe exercised refusal directly: opening Report and pressing
Enter before the initial read completed. That probe captures the retry state at
Home and End across all six sizes, then exports after one fresh Enter press. Its
thirteen captures and before/after reconciliation show unchanged source bytes,
context manifest, findings, decisions, jobs, allowance revisions and request
counts. This is additional native state/interaction evidence, not thirteen more
journey-machine passes.

Independent reconciliation retains three fixed Scan jobs, four attempts
including one cancellation, four observations and three human decision records
for two findings. Accounting remains five of seven calls, one unsettled
reservation and two unused protected Review calls. Dollar cost stays unavailable.
The temporary missing context manifest is restored byte for byte. No completed
queue is injected, and no additional job or model request is created by the
probe.

## Screen review and remaining limits

Fourteen final ANSI cell replays were inspected: eight probe frames spanning all
six sizes, compact paging and explicit export, plus six full-journey frames for
context result, spending stop, partial Scan, final Report, restart and missing
context. They use Menlo and a chosen background. They are terminal-cell
reconstructions, not OS screenshots or formal operator approval. The fixed
retry state remains readable at 40 columns without moving the destination or
requiring the operator to find an error paragraph. The full workflow still has
dense metadata and controls at narrow widths; twenty formal judgments remain.

The same review records three follow-ups in `ux-observations.json`:

- Compact Scan chrome can say `idle` while the owned study has a running job.
  `has_running_work` excludes the owned dispatcher. Check activity projection
  and exit/cancellation disclosure together before changing that predicate.
- Approval repeats model and finite-limit facts across several sections. Improve
  hierarchy while retaining exact frozen terms and the existing approval gate.
- General-context producer inventory/source receipts and grounding verification
  are different facts. Inspect their Report projection without presenting missing
  grounding verification as proof.

Provider transport is strictly intercepted. The fixture uses GPT-5.5 with medium
reasoning and inert owned greeting source; it establishes workflow behavior,
not live model usefulness or detector accuracy. Five intercepted requests are
recorded, with no source execution or live request. Cumulative live experiment
usage remains sixteen and no approved live capacity remains.

Evidence root: `scripts/devex/artifacts/complete-investigation-ux-20261024/`.
The first native failure, failed regression, final logs, input/program hashes,
capture provenance, probe and independent reconciliation are retained. The
previous fourteen staged files remain byte-identical while this separate Report
draft stays local on `main`. No broad delivery milestone is closed.
