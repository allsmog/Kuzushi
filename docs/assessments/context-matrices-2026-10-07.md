# Finite context results and accounting recovery

This increment makes recorded context cases readable and comparable in the
native TUI. It remains part of the larger bounded-investigation implementation.
It does not establish complete repository-to-report acceptance or visual parity
with the reference applications.

The result reader refreshes on entry instead of reusing a pre-run cache. Each
case retains its own completion and recurrence counts. Operators explicitly
choose a completed baseline pass and a candidate pass. Returning from comparison
restores the case and pass selection. Long case details and pass lists remain
reachable by keyboard, and narrow labels preserve their distinguishing names.
Pending or unreadable comparison snapshots do not display apparent zero counts.

Accounting failures block continuation and retain known consumption, unresolved
requests, edited limits and the investigation identity. The header labels these
values as last-read counts; detailed budget text says they are unverified until
recovery. A successful retry restores the same allowance. Discovery-pass copy
now distinguishes defaults for new cases from existing case repetitions.

## Evidence

The final native J109 run is
`/tmp/kuzushi-context-matrix-20261007/tui/20261007-143450/J109`.
It has 46 machine passes, no machine failures, eight passing audit judgments and
47 captures across 40×12, 60×20, 80×24, 96×89, 120×36 and 160×48. The driver
retains raw `REVIEW_REQUIRED` and exit 4; the separate `manual-review.json`
records the judgments. No-color restart, explicit baseline selection,
comparison return, ledger failure and recovery are covered.

The owned greeting source is never executed. Every provider request is
intercepted. Nine requests produce labeled synthetic observations, with
Alpha 3/3, Beta 2/3 and Gamma 1/3 recurrence. The missing Beta observation is
shown as not observed, without a fix claim. Source content and the globally
active Gamma context remain unchanged. The ledger retains nine settled calls,
nine work attempts and two protected review calls under the eleven-call limit.
There are no new live requests or live-model accuracy claims.

Focused checks pass: 107 study-flow tests, 21 comparison tests and five
accounting presentation tests. Workspace build and all ten quick verification
gates pass. The CRAP-risk gate passes for the pending code changes. The summary
receipt discloses a dirty tree; it is not a clean-commit certification.
The final native SHA-256 is
`b9a27dd2e76364e8de0d003bd7b5055c164ed28ff843eb6e2cd8c42374c0e962`.
The code/scripts source hash stayed unchanged throughout the final capture.

Earlier J109 failures remain preserved under the same evidence root:

- `20261007-135149`: navigation did not reach the approval checkpoint.
- `20261007-135608`: pre-run cache incorrectly showed zero completed passes.
- `20261007-140223`: baseline selection had no visible confirmation.
- `20261007-141406`: machine checks passed, but narrow labels were
  indistinguishable and comparison capture was premature.
- `20261007-142552`: the ledger-failure screen hid retained call consumption.

The first quick verification failed on fixture formatting. Focused diagnostics,
the formatting correction and a subsequent green summary are retained in
`/tmp/kuzushi-context-matrix-20261007`.

## Remaining work

Matrix report/export integration, case label editing and selected-case context
inspection remain open. Native budget exhaustion, partial jobs and cancellation
still need their own acceptance evidence. The report cache currently clones its
value for each projection and needs performance evaluation on larger ledgers.
The job deck also needs clearer case/pass labels instead of truncated generated
ids. Module functionality certification, monorepo scope review and reviewed
learning artifacts remain part of the larger plan. No delivery milestone is
closed by this increment.
