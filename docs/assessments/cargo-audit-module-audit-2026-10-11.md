# Cargo audit execution and operator controls

Cargo audit now produces dependable scoped dependency signals through shared
prepared dispatch. An installed offline scanner reads an exact lockfile snapshot;
Review and Report consume its preserved observations. The tool remains Core
with limited evidence. A package declaration matching a published advisory does
not establish deployment, source reachability or an executed vulnerability.

The audit found a readiness/execution mismatch: availability probed the standalone
binary, while execution invoked the Cargo shim in the target. The executor now
invokes the selected standalone binary, feeds captured lockfile bytes on stdin
and uses an isolated working directory. It reads no target toolchain or audit
configuration. Capture rejects missing, nonregular, symlinked, oversized and
invalid UTF-8 inputs before process execution. Direct missing-lockfile output is
failed work, preserving the legacy public unit scanner's empty-file contract.

Options declare the binary, database, offline/stale choices, job time allowance
and lockfile byte bound. SAST reuses those descriptors through prefixed options;
unused or unknown controls are refused. Network remains enabled by default for
compatibility and is disclosed before approval. Offline explicitly adds both
no-fetch and no-yanked behavior. Time is shared across captures and roots;
default 600000 ms and 16 MiB per file have maxima of 86400000 ms and 64 MiB.
Whole-repository source authentication remains separate. Cancellation, deadline,
bad exit status and unreadable output cannot become clean results.

Selected child directories now work when the workspace has no root lockfile.
Their structural identities include the scoped lockfile path, separating the
same advisory/package/version in independent lockfiles. Root identity stays
unchanged. Exact-file membership remains refused. Only the directory-root
lockfile is inspected; nested lockfiles and application behavior are uncovered.
The DAG context edge remains display metadata, as direct dispatch demonstrates.

Thirty focused core checks, 19 allowance-review checks, two Semgrep regressions
and the registry policy inventory contract pass, totaling 52 distinct checks.
The locked workspace build passes. Risk checks pass for 410 changed production
files at this checkpoint. Final repository verification is recorded at
`/tmp/kuzushi-cargo-audit-20261012/final-verification.json`; dirty/drifted receipts
remain unsigned.

Final sequential J219 is
`/tmp/kuzushi-cargo-audit-20261012/review-navigation-tui/20261011-224836/J219`.
It has 42 machine passes, zero failures and 32 authenticated text/ANSI capture
sets at six terminal sizes, plus no-color restart. The native binary is
`/tmp/kuzushi-cargo-audit-20261012/native/kuzushi`, SHA-256
`1a1c19e7a773652725fb40b90c32f13598127436f43eba379eaeb38e909420dd`.
The installed cargo-audit is 0.22.2, binary SHA-256
`49e597c7f2d74bcb37946f538ecd4a9bad492b8491c78556fb3b0a537b4d8ae5`.
Its copied advisory database authenticates 1315 source files. Original operator
configuration and cache remain untouched.

The hypothetical fixture declares time 0.1.40 without application source.
Actual installed output matches RUSTSEC-2020-0071. Target-local ignore settings
cannot suppress it. The journey retains an earlier failed missing-lockfile
attempt, then installs source metadata, builds and explicitly accepts a verified
manual context, approves exactly three jobs with one worker and 60-second/1-MiB
limits, and runs them offline. Three observations consolidate into one signal.
A deferred decision through the manual control survives JSON export and restart.
Provider reservations remain zero, work attempts remain three, and one protected
future Review call remains unspent. A selected shared model is required to
reserve that future capacity; frozen scan execution correctly names no model.
All fixture source and database hashes remain unchanged after source setup.

Four visual judgments retain raw REVIEW_REQUIRED. Assistant capture inspection
is separate from operator acceptance. At 40x12 the Report pages expose recurrence
and honest incomplete-coverage copy. This metadata-only Map uses its acceptance
card and has no runtime data-flow summary. The existing stale chrome is observed
after deliberate source setup; current-checkout applicability is not qualified
by the fixture hash check.

Six predecessor attempts remain preserved: an immediate result check raced
publication; a direct SQLite checkpoint failed while the TUI was active; the
initial context omitted the deterministic lockfile surface; the next expected
an application summary from metadata; one navigation sequence opened Source
instead of allowance; and future Review capacity lacked a selected model.
The settled harness uses bounded publishing waits, the existing safe ledger
reader and observed controls. No failed receipt is rewritten.

A preceding 41-pass run remains at
`/tmp/kuzushi-cargo-audit-20261012/selected-review-tui/20261011-223142/J219`.
Its last title match could be satisfied by Campaign before the submitted open
command finished. Final capture waits for actual Review, preventing that weak
assertion from qualifying restored finding navigation.

Production does not pin the advisory database's content identity or independently
measure its freshness. Every CLI configuration/version, large-input throughput,
cross-platform behavior, complete absence reasoning and full operator/reference
acceptance remain open. The matrix now has 78 scoped assessments among 113
visible tools, with 35 unassigned including eight excluded tools. No maturity
promotion, speculative retirement or broad delivery milestone follows this test.

The October 13 integration refresh replaced a stale false-clean shell test with
failure and successful adapter checks. It also corrected the single-condition
native resource preview and deferred-finding Report handoff. Final J219 records
48 machine passes, zero failures and four open visual judgments, using the same
installed scanner and a fresh offline database copy. Three jobs, observations
and one human decision survive export and restart with no provider requests.
See the [integration recovery assessment](tui-integration-recovery-2026-10-12.md#offline-cargo-audit-and-accurate-resource-preview-october-13)
for current receipts and retained failed attempts. The module's qualification
limits above remain open.
