# Auxiliary scanner settlement and missing dependencies

Direct Go and CodeQL adapters now authenticate the final source before committing
observations and run status. Source changes retain partial work and the original
failure, rather than presenting a completed scan. Canonical stored
`findings.json` snapshots include empty results. Untraced library calls publish
under the run identity that actually received their observations.

The Go adapter rebinds selected-directory observation identities to the workspace.
Its advisory policy remains unrecorded, so a later missing advisory cannot
establish reassessment. Controlled IO tests cover positive, empty and failed
source changes. These controls are not installed Go engine qualification.

CodeQL remains an auxiliary Labs action whose observations cannot complete Scan.
Source changes suppress static-evidence indexing and disclose that omission.
The original SARIF reports survive until persistence. Source refusal names the
requested action while retaining the original error chain. An actual installed
`codeql:create-db` refusal now says `codeql:create-db source check refused`,
rather than labeling the operation as a vulnerability patch action.

Native J303 exposed a separate shared-routing defect: the registered Go action
was absent from the native executor dispatch predicate. Prepared shell dispatch
now reaches its executor and reports the actual missing binary. A focused router
regression covers this boundary. All 18 registered native handler names agree
with the shared route after the correction. Catalog maturity is unchanged.

## Verification and limits

Evidence root: `/tmp/kuzushi-auxiliary-scanners-20261016`.
Fifty distinct focused Core checks pass, including parser, settlement, source
labels, reassessment, receipts, direct coverage and shared routing. The current
workspace build and all ten summary checks pass. The risk proxy passes for 175
changed production files and its 15 support checks. The summary receipt is dirty,
unsigned and reports `driftedDuringRun: true`; it is development evidence.
Documentation is checked separately after this update.

Final J303 is `native/J303/20261016-045750/J303`: 17 machine passes, zero failures,
11 capture pairs and three pending human judgments. It exercises the real
missing-dependency path through prepared shell dispatch, Report and no-color
restart at six terminal sizes. Its native SHA-256 is
`83966a220ba12e4983c4c4aabfba004372821d537a4688072346bcccbd4d2521`.
All 13 programs, 4,290 source inputs and 734 runtime inputs retain their frozen
hashes. `native-evidence.json` verifies capture dimensions, text/ANSI/provenance
hashes and absence of explicit color selectors after restart.

Selected ANSI cell replays were inspected visually. They are not OS screenshots.
At 40x12, the outcome and start of the missing-binary cause remain visible with
paging controls; the complete installation command requires scrolling. Report
retains the failed dependency and states that finding review completeness does
not describe repository coverage. These observations leave all three operator
judgments open. Earlier failed routing and reader-wait cases remain preserved.

Govulncheck is absent from the installed environment. No scanner download, Go
package loading or successful installed Go scan is claimed. The installed
CodeQL 2.25.4 compiler accepts one owned marker query using copied local library
packs, without downloads. Actual database preparation on the existing source
fixture is refused by source authentication. A separate three-file inert fixture
is staged in a temporary repository; its local commit awaits the operator's
specific go. There is no successful real CodeQL database/query qualification
from this increment. The earlier inert protocol fixtures remain distinct.

There are zero new provider requests, target program executions, Git commits or
pushes. Fourteen earlier provider requests remain spent. General scanner
usefulness, installed successful execution, whole-operation resource bounds,
every persistence-fault timing, human UX acceptance and the full original
investigation plan remain open. No module promotion or retirement follows.
