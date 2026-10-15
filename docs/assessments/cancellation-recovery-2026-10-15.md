# Operator cancellation and bounded investigation recovery

The combined investigation journey exposed an operator Stop being recorded as
an interrupted child. The dispatcher now preserves the Stop cause separately
from lost or invalid session control. Operator cancellation parks unfinished
jobs as canceled. Invalid control and unexpected shutdown remain interrupted.
The canceled attempt stays consumed and unresolved provider work remains
reserved. Retrying still requires a reviewed attempt allowance.

The shared run-artifact boundary holds the terminal lock while reaping the owned
child and recording cancellation. Recovery readers cannot repair the dead child
between those operations. An already terminal result wins the race and is kept.
This includes a published typed outcome awaiting its final summary. Open model
and tool calls, tasks and plans close with the actual stop disposition before
the terminal receipt. Their cost remains unknown and provider reservations are
not settled by this local process stop.
Completed Scan acceptance references each fixed trial's final successful run.
Canceled and superseded attempts remain in the queue and report evidence.
Partial acceptance keeps every attempt reference. Report readers accept the
exact final-run set or the legacy exact full-attempt set, and reject arbitrary
subsets. This changes no persisted artifact format or finding verdict.
Stopping a child before its start record does not manufacture execution metadata.
The shell explains an operator Stop and offers partial reporting or plan review.
It retains focus and the composer draft. A prior canceled queue cannot hide a
new source or execution error.

## Bounded native case

J121 now includes an admitted intercepted request held open for the real Stop
control. Its three fixed discovery jobs follow executed Map preparation and
explicit context acceptance. The first pass completes, the second is canceled,
and the third remains unstarted. The operator then reviews a two-attempt limit,
continues to the original call boundary, reports partial findings and explicitly
revises the call allowance before finishing the same plan. Restart and export
must retain all attempts, decisions, recurrence and unresolved accounting.

The transport replaces every fetch and has no network fallback. Its credentials
are synthetic, its observations are explicitly labeled, and target source is
never executed. It cannot establish real-model detection quality. No queue
completion, finding decision or successful response is injected for the canceled
request. The original failing run is retained under
`/tmp/kuzushi-cancel-integration-20261015/initial-tui/20261015-005223/J121`.
The first rebuilt candidate is also retained under
`final-tui/20261015-010938/J121`. It reached cancellation and the original call
boundary, but its open lifecycle calls blocked partial phase publication. The
reporting guard correctly refused that degraded stream. Neither failing run
qualifies the combined workflow.
The second rebuilt candidate, `replacement-tui/20261015-012154/J121`, reached
all three completed jobs and preserved its five intercepted requests. Completed
Scan publication then correctly refused to call the earlier canceled attempt
complete. It is retained as the regression for final-run selection versus
historical evidence; it is not a passing acceptance receipt.

The final frozen bundle passes 135 focused Rust tests: eight phase-handoff,
20 report, five stop, 19 recovery, 75 campaign and eight TUI checks. One native
fixture setup test is intentionally ignored. Empty filtered invocations are
retained but are not credited. The locked workspace build and risk proxy pass.

Final J121: `v3-tui/20261015-013609/J121`, with 123 machine passes, zero failures
and 96 live text/ANSI capture pairs. Seventeen human judgments remain pending.
The assistant inspected the cancellation and allowance notices, partial and final
receipts, accepted Scan, compact Report controls, no-color restart and missing
context result. The forty-column views retain paging and action controls.

The journey ends with the same three discovery jobs, four retained Scan attempts
including one cancellation, five intercepted requests, four raw observations,
two findings and three durable human decision records. The seven-call allowance
retains one unresolved reservation and two protected Review calls. No live model
request or target source execution occurs. No queue completion is injected.

Thirteen executables are frozen. The native SHA-256 is
`7c98ee0b6cb7d138d7d861119b24fd52e56446d84c40f7289067bece9c75e8b1`.
All 4,143 Rust/build input files remain identical before tests, after the locked
workspace build and at capture review. Runtime and journey inputs also match
recorded hashes. See `native-v3-manifest.json`, `source-v3-before.json`,
`source-v3-after.json`, `v3-runtime-inputs.json` and `v3-assistant-review.json`
under `/tmp/kuzushi-cancel-integration-20261015`.

Campaign rows still show the current legacy retry counter rather than cumulative
admissions. The generic Report hint also calls incomplete records interrupted.
These presentation details, canceled-only observation recurrence and the human
judgments need separate qualification before full operator acceptance.

Human judgments remain separate from machine assertions. The eight-request live
allowance remains exhausted and the separate Scan allowance is still unanswered.
This checkpoint does not establish complete product acceptance, reference-product
parity, physical latency or qualification across every platform and workload.
