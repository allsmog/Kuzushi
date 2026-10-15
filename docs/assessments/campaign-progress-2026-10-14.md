# Campaign progress stays visible while reading

October 14, 2026. Local changes on main at `f8649511f746`.

The wide-scope experiment showed a completed Campaign at 40x12 with its job
counts below the initial document viewport. The fixed row previously showed
only reading position. It now uses the same recorded job-count projection as
the full summary. Job totals and state counts stay visible while paging,
inspecting a job and resizing. Position remains beside the counts when it fits;
otherwise the header retains the workload and paging hint. Long mixed-state
breakdowns shorten visibly in narrow headers; the complete counts remain in
the document. The campaign list keeps its own reading position rather than
presenting one selected campaign's jobs as the entire list.

The change reads the existing snapshot. It does not advance phases, modify
inclusion, change a plan, grant allowance, start work or infer a fix from a
missing observation. Existing action-result priority, cancellation controls,
input ownership and navigation remain. Unknown spending stays in the original
summary and receipts. The shared human label is now `Jobs: N`; artifact and
public module formats are unchanged.

Fifty focused Campaign tests pass. New coverage exercises completed counts in
Prompt and Navigate modes at all six sizes and multiple offsets, retained draft
and cursor, unchanged selection, the full mixed completed/running/failed/parked/
planned breakdown, and list-mode identity. The locked workspace build and all
ten quick-summary gates pass, including 391 Node tests and the CRAP-risk proxy
for 721 changed code files. The unsigned local receipt is
`/tmp/kuzushi-tui-integration-20261012/campaign-progress-green-receipt.json`.
It records `dirty: true` and `driftedDuringRun: true`; this is not a clean
release, full Rust suite, full CI or platform-matrix claim.

J268 at
`/tmp/kuzushi-tui-integration-20261012/campaign-progress-verified-tui/20261014-190413/J268`
passes 29 machine checks with 16 live text/ANSI capture pairs on native SHA-256
`e2098c38a40c7d8eae42572b8ae64631743ad09ed345dc7ba442314eb2b239bb`.
It reads the actual previously completed 24-job Semgrep study over 4105 inert
source files. A composer draft survives paging and 40x12, 60x20, 80x24, 96x89,
120x36 and 160x48. Enter inspection, q return and forty-column no-color restart
preserve the exact completed workload. Source hashes, plan and queue hashes,
27 observations, nine scripted decisions and zero provider reservations remain
unchanged. No scans, model requests or source execution occur.

The first J268 run is retained at
`/tmp/kuzushi-tui-integration-20261012/campaign-progress-tui/20261014-190236/J268`.
Its generic navigation probe could not recognize the compact footer, though
inspection and return worked. The final script uses the visible Escape control
and asserts `Esc compose`. The common harness is unchanged. Capture integrity
and qualified assistant review are separate from the raw `REVIEW_REQUIRED`
result. Three human judgments remain pending; physical contrast, motion,
hardware latency and reference-product parity remain unqualified.

A separate acceptance review rechecked the unchanged inventory implementation:
16 inventory-boundary tests and ten inventory-derived shard tests pass. One
initial filter selected zero tests and is not counted. These checks cover bounded
walking, partial receipts, cancellation, containment, parent-file preservation
and finite candidate splitting. They do not close the broader delivery checklist
or qualify every module. The eight-request live-model allowance remains spent.


A later [application-study preflight](prepared-application-model-test-2026-10-14.md)
found an uncovered case: short selected-job documents lost the header when they
fit on wide terminals. The original fifty-test and J268 evidence did not cover
that combination. The follow-up keeps selected-job headers regardless of length
and adds a focused regression plus six-viewport native coverage. Earlier receipts
remain unchanged.
