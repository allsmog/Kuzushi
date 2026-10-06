# Study resource preview

October 6, 2026, local uncommitted implementation on `5dcaa600e`.

The live OAuth validation recorded four requests for one completed discovery
pass but no dollar price. The prior spending selector discarded it because it
only accepted exact dollar receipts. The new **Usage evidence** row keeps
provider-request observations independent of pricing and separates historical
usage from estimates of future work.

The shared accounting reader authenticates an admitted run against its historical
work approval, source/config identity and request attribution. It preserves
unresolved requests, detects ambiguous ownership and changed records, and leaves
missing legacy evidence unavailable. Reading starts no work and changes no
approval or consumption. `campaign:allowance runId` exposes these counts through
the normal prepared dispatch path.

Projections require matching recorded source, context, options, model and runtime
conditions, complete engine execution and settled request evidence. The preview
labels a single historical scan as limited evidence, includes all planned maximum
starts and compares requests against proposed capacity after commitments and
protected Review calls. It gives no enforced upper bound or dollar guarantee.
Changing source or conditions withholds the projection while retaining the past
observations. Unknown dollars never become zero.

`campaign:study baselineRunId` freezes the selected reference in existing plan
metadata. It stays out of scanner input. The authenticated choice survives
restart; changing it invalidates the draft and requires a new plan review while
preserving options, limits and spending. Existing public Rust plan/receipt
layouts stay intact. Historical dollar costs remain readable, but legacy costs
without authenticated conditions no longer produce an unchecked future estimate.

Native cold-start validation exposed a supported-path defect: the shared
projection writer created all findings tables without the schema stamp expected
by a subsequent read-only findings consumer. The common schema owner now stamps
successful initialization and rejects newer versions before writing tables.
Read-only consumers still perform no migration. This fixes headless planning
followed by allowance approval without requiring a TUI launch to initialize the
database.

Focused checks pass: six admitted-run/shared-dispatch tests, five pure projection
tests, four study-receipt tests including alias/path/digest recovery, eight TUI
configuration checks, six schema-named checks and 28 projection regressions.
Workspace build and the CRAP-risk proxy pass. All ten quick gates pass in
`.git/bounded-investigations/provider-usage-final-gates.json`, finished
`2026-10-06T07:57:23.120Z`. Dirty source and conservative drift remain explicit;
the receipt excludes full CI and the platform/release matrix. Documentation
closeout follows that receipt and is checked separately.

J91 at `/tmp/kuzushi-bounded-investigations-tui/20261006-005118/J91/` records
18 machine passes and five separate passing screen judgments. Raw
`REVIEW_REQUIRED` remains. It exercises six terminal sizes, actual 40x12 paging
to 40/40, the approval document, cancellation, actual exit and no-color restart.
The real bounded executor receives explicitly intercepted invalid/repair
responses and synthetic observations. Four fixture requests remain recorded
across two completed passes; the selected pass used two requests. Three future
jobs remain unstarted, with one allowance revision and unchanged source bytes.
The native SHA-256 is
`feda76fea1a19078973c5e97bd33edbf606fda3bec74d2d6ec78b89d5e60c320`.
No live inference or source execution occurs in this journey.

Failed predecessors remain: `20261006-003007/J91` exposed the missing schema
stamp; `20261006-004147/J91` invoked the raw campaign dispatcher, which correctly
refused a scan batch; `20261006-004513/J91` had an incorrect origin caption and
insufficient narrow paging. Their raw failures and independent judgments are
preserved. A compilation disk-space failure was recovered by removing only
generated core/TUI package artifacts. Source files and saved run evidence remain.

A separate normal CLI query read the real OAuth pass's four requests without
inference. Its ledger remains six total consumed requests, zero unresolved,
four work attempts and two protected Review calls. No additional live context
request is authorized. The prepared diagnostic test still awaits its specific
allowance approval.

This increment does not certify scan precision, model usefulness, full module
readiness, reference interaction parity or large-history responsiveness. The
complete context/scan/triage/report journey, finite multi-scope execution,
context experiments and reviewed lessons remain open.
