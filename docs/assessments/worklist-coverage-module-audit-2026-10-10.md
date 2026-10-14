# Advisory ranking, bounded reads and reliable worklist recovery

Prepared dispatch reproduced five contract defects: worklist ranking counted as
a Map result, its declared target was ignored, unsupported fan-in requests
silently succeeded, coverage limits accepted invalid values and coverage reads
initialized an existing database. The initial contract run failed all five
checks. The corrected suite passes seven checks, including parent/child finding
isolation and honest exhaustion of large coverage history.

## Functional contracts

`worklist:rank` is auxiliary Map work with `phase_result: false`. It resolves its
canonical selected target and opens only an existing child finding store,
read-only. Parent findings never stand in for child history. `includeFanIn` and
its aliases preserve false/default behavior and explicitly refuse true. The
public gathering adapter enforces the same refusal and 1 through 500 row limit.
Results retain rows, raw citations, contributor states and total population,
adding `target` and `sourceFreshnessVerified: false`. Summaries name shown/total
counts and contributor issues. This is inspection priority, not confidence,
severity, vulnerability verification or finding-fix evidence.

`coverage:recommend` remains Operate without a phase result. Shared preparation
validates limits from 1 through 500. Results add total count, canonical target
and advisory/freshness meaning. Inputs are saved context, available finding
history and historical Git baselines. Missing baseline records and missing
finding history cannot establish actual scan or finding absence. Priorities and
saturation weights are heuristics, not measured precision or calibrated value.

Existing coverage databases now open through the shared secure read-only SQLite
adapter. Version 0, future versions, incomplete schema and unsafe paths are
refused without initialization or migration. Missing databases are not created,
including the sweep inspection path. Explicit writable producers remain intact.
Tests preserve existing database bytes and refuse writes and outside symlinks.

Baseline materialization stops at 10,001 rows and refuses history above 10,000.
Recommendation finding reads project current paths using the existing safe
identity fold, without finding/source hydration. They refuse more than 10,000
current paths. These are returned-data limits. SQLite grouping, sorting,
identity-folding work, total bytes and total latency remain unbounded by them.
No model calls or graph builds occur in the audited default path. Opt-in deep
ranking, cancellation during large database queries and aggregate workload
limits remain unqualified.

## TUI behavior and native evidence

Worklist rows, complete paths, raw values and degradation reasons now wrap
before viewport paging. Shown/total counts and unverified freshness remain
visible. Empty results preserve degradation explanations and executable `run`
guidance. Explicit child results neither overwrite the parent snapshot nor
auto-open a parent gallery as the child result. Focus, draft and cursor are
protected by a focused application test.

Native screen review found a restart defect: the reader depended on an
attack-surface artifact attached to the latest run. The worklist now reads saved
context through existing asynchronous hydration and requests recommendations
for its gallery. New snapshot binding uses the saved context content hash;
unchanged rehydration preserves a returned cap, while regenerated context
invalidates the earlier capture. Missing/loading context retains the historical
run-artifact compatibility source. Malformed saved context is disclosed.
Restart reconstructs the default projection; exact earlier tool options remain
in their receipts. This does not claim persistent worklist selection or complete
investigation recovery.

Final J160 is at
`/tmp/kuzushi-worklist-audit-20261010/verified-reading-tui/20261010-033019/J160`.
It has 34 machine passes, zero failures and 36 authenticated native tmux text/
ANSI captures. Native SHA-256 is
`c3d332f793f9664beb5101a13bf49490998306680a7e5d24986e2188ed4dcfb2`.
The six viewports are 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48, followed
by no-color restart. Normal Page Down reaches every path/evidence fragment and
contributor state at 40x12. Two body rows fit there, so full reading takes many
pages. The raw verdict remains REVIEW_REQUIRED. Six assistant judgments are
separate in `assistant-screen-review.json`; operator approval remains false.

Actual deterministic context preparation feeds four root rows and one child
row. Headless CLI context/ranking and shell ranking use the same prepared
executor. Root receipts retain six completed and one failed ranking runs;
invalid zero limit is rejected before a run starts. A malformed ledger is
unchanged by reads, then repaired by separately recorded synthetic fixture
setup. Fresh contributor evidence establishes recovery before restart. Source
hashes stay unchanged. Findings, work attempts and provider reservations remain
zero. This fixture runs no scans, models, source, exploitation or patching.

Earlier retained attempts caught an incorrect fixture receipt filename, an
Escape-based navigation helper leaving the gallery, a header-only restart check,
context-version invalidation dropping the returned cap and a stale-count match
while repair work was still running. The final journey asserts actual worklist
focus, exact completion/errors, contributor evidence and receipt counts.

The limit error is truthful in logs, but an undismissed earlier error can remain
in the notice banner. Error prioritization, removal of internal phase labels in
the contributor legend, selectable file detail and full reference-product UX
parity remain open. One screen judgment is partial for this reason.

## Verification and remaining scope

There are 161 distinct focused passing tests: 60 Core and 101 TUI, including
read-only/schema/window contracts, existing rankers and shared registry behavior,
saved-context hydration, same-content cap preservation and regenerated-context
invalidation. The workspace build and CRAP-risk proxy pass, with 607 changed code
files assessed. All ten repository summary gates pass; the receipt is copied to
`/tmp/kuzushi-worklist-audit-20261010/verify-receipt.json`. Final release, port,
public identity, command-drift, CodeQL latency-contract and retired-runtime
documentation checks pass. Dirty/drift metadata includes the inherited dirty
tree and this increment; it is not evidence of a concurrent writer.

Qualification is scoped to these default advisory readers. It does not promote
or retire a module, validate finding quality, certify full repository coverage,
approve model spend or close any of the nine broad implementation milestones.
Work remains uncommitted on main. Live model validation still needs its specific
test allowance; no credential renewal or provider request occurred here.
