# Study usage loading

October 6, 2026, local implementation on `5dcaa600e`.

Opening or refreshing the study form previously loaded every completed scan and
its detailed accounting synchronously. Historical usage now uses the existing
background view reader. The constructor creates only presentation state, and
rendering reads cached values. Catalogue loading inspects the most recent 100
run records and discloses a truncated choice window. Detailed receipts and
accounting are read only for the explicitly selected run. The shared cache keeps
at most 32 named usage results.

A frozen plan can name an older baseline outside that window. Its choice remains
selected while loading, after a failure and after restart. Completing a read
updates usage information without changing the cursor, scroll, draft, navigation
origin, plan, allowance or focus. Changing the selected baseline remains an
explicit action that invalidates the draft plan. Refresh cancels the old view
reader generation and reloads usage; failed reads wait for explicit refresh.
Errors and unknown charges produce no zero-cost inference.

The shared view reader still has at most two background workers. Cancellation
is checked before catalogue loading and between returned records. A blocked OS
or SQLite call cannot be interrupted mid-call. A cold or stale shared run-history
index can rebuild from canonical metadata in the background; the 100-record
choice window does not claim a bound on that index rebuild. Very large history
performance and cross-platform terminal behavior remain separate acceptance work.

Verification passes: nine core history/projection tests, 57 view-reader
regressions, eight study-configuration regressions and eight presentation/control
checks. Workspace build and the CRAP-risk proxy pass. All ten final quick gates pass in
`.git/bounded-investigations/usage-hydration-final-gates.json`, finished
`2026-10-06T08:51:08.243Z`. The dirty source state and conservative drift are
explicit. Full CI and the platform/release matrix remain excluded; this final
receipt annotation is checked separately.

J92 at `/tmp/kuzushi-bounded-investigations-tui/20261006-014637/J92/` has
23 machine passes and five separate passing screen judgments. Its raw
`REVIEW_REQUIRED` result remains unchanged. Captures include all six terminal
sizes, actual 40x12 paging to 44/44, broken-baseline refresh and recovery, approval
cancellation, real exit and no-color restart. The native SHA-256 is
`363b686f3232706c78d16929ed9a4c39dcac491e5694a38ef2bbd74b8ed7d287`.
The fixture adds 104 explicitly labeled synthetic history records around the real
executor with intercepted transport. Four intercepted requests, one approval
revision and zero future starts remain unchanged. Source bytes and the restored
baseline metadata match their original values. No live inference or source
execution occurs.

The predecessor `20261006-014014/J92` has 23 machine passes but a failing screen
judgment: refresh was functional but absent from visible controls, and the error
led with a long path. The new failure state leads with retry and selection
actions and retains the baseline before details. Refresh/reload appears in the
footer at every supported width. The original failure and captures remain.
Initial compilation, CRAP and slow-reader test failures are retained in local
logs. The slow-reader test originally expected a cached result after cancellation,
although cancellation can correctly discard it; it now checks input response,
reader completion and stable focus.

New copy passed the applicable register review. This increment does not certify
full module readiness, model usefulness, complete investigation acceptance,
physical-terminal latency or parity with the design references. No additional
live inference was performed.
The prior real-model allowance remains six consumed requests, zero unresolved
and two protected Review calls. The additional context diagnostic is unapproved.
