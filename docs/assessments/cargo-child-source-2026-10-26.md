# Selected dependency source and retained package locations

Direct child-directory advisory scans now register and verify source in the
explicit parent workspace. Discovery still reads only the selected Cargo.lock.
Native path components preserve a Unix directory named `client\scope` separately
from `client/scope`. Direct and SAST observations agree on each lockfile's
structural identity. Existing observations and human decisions remain unchanged.

Four prepared-dispatch regressions first reproduced unverifiable parent source,
collapsed literal paths, different direct/SAST identities and completed work
after a parent edit. They pass after the ownership and rebinding correction.
A changed parent source preserves observations but keeps work partial.

## Package source locations

The first installed-scanner TUI repeat passed its machine checks but failed
screen review. Every advisory pointed to line 1, so retained source ended before
the affected package name and version. Paging could not reveal omitted lines.

The adapter now parses package-name spans from the exact captured stdin bytes.
An advisory's structural package/version locator selects its declaration line.
No live lockfile reread occurs after execution. Duplicate package/version
declarations, missing packages, invalid metadata and missing locators produce an
unavailable location, not an arbitrary match. The raw observation is retained.
Scoped source binding then reports partial work when that location cannot be
authenticated. Line zero now explicitly reports that no source line was recorded.

Physical line counting handles comments, reordered fields, UTF-8 and CRLF.
Sorted spans consume disjoint byte ranges. Package locations do not change
finding fingerprints or structural locators. Stored historical line-1 anchors
are not rewritten; a new observation supplies a new retained source location.

## Verification

All 51 distinct focused Rust checks, the locked workspace build, Core/TUI/CLI
all-target Clippy and changed-code risk pass. This includes a controlled live
lockfile edit after stdin capture and explicit unavailable/ambiguous cases.
Protocol fixtures are labeled; installed execution is separate evidence.

Final sequential J384 is `native-attempt-3`, with 27 machine passes, zero
failures, 27 authenticated text/ANSI capture pairs and four answered agent
screen questions. The agent result is `PASS_WITH_FINDINGS`; raw exit 4 remains
`REVIEW_REQUIRED`, and operator acceptance remains false.

Six real module scans using installed cargo-audit 0.22.2 retain five advisory
observations, two distinct findings and one scripted deferral. The owned fixture
contains hypothetical time 0.1.40 metadata, not a running application. No target
build or source execution occurs. Report names only the selected parent
Cargo.lock and one inspected file after its empty scan. Neither child finding
is resolved. Unknown advisory policy cannot establish reassessment from absence.

All five source files and copied database files remain unchanged. All six source
snapshots belong to the parent. A nested lockfile is deliberately uninspected.
No model, provider request, accepted Map/Scan checkpoint or follow-up job occurs.
The native SHA-256 is
`8cde443ea594b3960ff1482a20d9b715b4dca349735bd14c51628cdec35cff43`.
The installed scanner SHA-256 is
`49e597c7f2d74bcb37946f538ecd4a9bad492b8491c78556fb3b0a537b4d8ae5`.
All 6,749 recorded inputs stay unchanged during the final run.

Eleven inspected ANSI cell replays cover six terminal sizes, compact source
paging, Logs, both selected findings, Report and no-color restart. Menlo 15 and
a chosen background are replay choices, not OS screenshots. At 40x12 the package
and version are reachable on page four. Logs and technical headings remain
dense, and narrow reading still takes substantial paging. Reference-product UX
and operator acceptance remain open.

The initial visual failure remains recorded. A second run passed machine checks
but used a weak wait that matched the nested path in the list while the literal
detail stayed selected. The final run explicitly returns to the prompt and
requires the nested detail path before qualifying that navigation. No production
input defect is inferred from the observer error.

Evidence is under `scripts/devex/artifacts/cargo-source-current-20261026/`.
Parent source authentication has separate IO and bounds from discovery. This
fixture has no Git commit, so it does not qualify a two-SHA transition, database
freshness/identity, large-input throughput, every platform or complete workflow.
Core maturity is unchanged; other scanner ownership requires its own evidence.
