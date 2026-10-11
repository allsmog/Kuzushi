# Matrix Scan acceptance and recovery

Matrix dispatch now publishes authenticated results into the existing Scan
journal after work drains. The report reader checks the approved plan, exact
case inputs and recorded attempts before publication. A result remains
unselected until the operator acts. No run references means no Scan attempt.
Completed work is complete; incomplete work remains partial or failed.
Recovery preserves the exact run set and does not duplicate the attempt.

The journal retains authenticated source snapshots. Changed content blocks
reuse while preserving observations and run references as history. A matrix
keeps each case's recurrence separate when ordinary Report entry reads the
accepted attempt. This change adds no work, recursion, model calls or allowance.

## TUI corrections

The native audit caught an inferred-page navigation defect: Use Scan resolved
the result, removed its page anchor and exposed Review. Use now pins the
current result page without resetting scroll or focus. Use & Review retains
explicit progression. The existing Map navigation regression test also checks
this distinction.

Receipt artifact references are bounded. The result card now labels their
count as receipt links, separately from the Scan panel's recorded-file count.
A stale cockpit test now follows the current pinned-detail contract when the
finding sits outside a filter. It asserts distinct fixture identities and
discloses which finding decisions target.

## Evidence

Final native J111:
`/tmp/kuzushi-matrix-handoff-20261007/tui/20261007-164533/J111`.
There are 17 machine passes, no failures, six passing screen judgments and
15 live captures. The raw result stays REVIEW_REQUIRED with exit 4.
Separate manual-review.json and ansi-review.json record the judgments.
Screens cover 120x36, 80x24, 60x20 and 40x12, with a real no-color restart.

The fixture creates owned, labeled synthetic receipts through the existing
application-call settlement API. It invokes no scanner executor or provider
and never executes target source. The native dispatcher recovers nine completed
jobs twice. One unselected Scan attempt becomes one human selection; all nine
run references survive. The report retains six raw observations, one distinct
finding and Alpha 3/3, Beta 2/3 and Gamma 1/3 recurrence. Source, context mirror,
completed jobs and accounting remain unchanged. The fresh test allowance has
eleven calls, two protected review calls and zero provider reservations.
Unavailable run-cost records remain disclosed separately.

Native SHA-256:
`faec47af344829ca2367d7e8bb39ae0fb054d5d63ce0bd4fb600e7b2f3ead343`.
Every final capture uses this binary on main at
`972e09ca5ae86de49d53f204dc28ac7f096f9baa`, with pending local changes.
The harness cannot report a canonical Git target for the generated non-Git
fixture. Its oracle and authenticated indexed snapshots supply source checks;
this does not claim a versioned-target or full live-model acceptance run.

Focused checks passed: 15 report tests, four batch phase-result tests, three
CLI matrix tests, the inferred-page selection regression, and 89 cockpit
tests. Workspace build and all ten quick repository gates passed. The risk
gate covered 207 changed code files. Receipt paths and logs are retained in
`/tmp/kuzushi-matrix-handoff-20261007`.

## Retained failures and limits

An initial archive-copy recovery failed because run artifacts still pointed
at the original target. The test now generates fresh receipts; it does not
rewrite authenticated history. Fixture compilation and source-correlation
failures, an outdated RESULT checkpoint, a transient resize capture and the
first cockpit test failure remain available. The 163053 native run passed
machine checks but failed screen review on navigation and artifact counts.
Those judgments remain separate from the final passing run.

This increment covers completed matrix recovery and ordinary Report handoff.
Partial work and source drift have core tests. Native allowance exhaustion,
cancellation, partial acknowledgement and restart still need coverage. Case
and pass names in the Scan engine list also need clearer labels. Broader module
readiness, monorepo scope review, learning and full reference-quality TUI
acceptance remain open. All nine implementation milestones stay unchecked.
