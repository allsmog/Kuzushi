# Model generation with partial source context

The earlier partial-context increment enabled inactive import and explicit Map
review. Model generation still failed before inference because its grounding
and source-bundle readers required complete entry-point coverage. The source
projection also omitted the catalog's recorded `snapshotCoverage`.

Generation now consumes authenticated recorded observations. It requires
`activate=false` before a query when catalog coverage is partial. The bounded,
row-safe source projection includes `snapshotCoverage`; the model prompt also
states that unseen entry points remain unknown. Existing source identities,
catalog authentication, byte limits, cancellation and allowance dispatch remain
in force.

A generated partial catalog receipt has `status=partial` and retains the
catalog digest, exact context digest, timestamp, source identity and observed
counts. Verification authenticates that receipt against the current partial
catalog. A changed digest, missing snapshot or later complete catalog cannot
promote the receipt to verified coverage. Older complete-catalog receipts still
fail against partial coverage. Complete-set consumers retain their strict
reader, including the explicit deterministic fold.

The shared generation tail stamps verification before persistence and includes
its warning in both output and the result envelope. An inactive useful document
therefore remains a partial result requiring explicit Map acknowledgment. A
failed source or coverage check takes precedence over the partial warning.
Immutable context and Report consumers retain the exact recorded verification.

The initial five regressions exercised partial output through the real registry
with finite accounted scripted queries. Their one-component fixture did not
prove immutable persistence. The subsequent
[workflow correction](generated-partial-context-workflow-2026-10-24.md)
requires actual saved references in positive generation cases and expands the
suite to eight checks, including study defaults, the source-only staged branch
and unchanged refine. Historical green counts below describe the earlier run,
not that stronger persistence qualification. No provider transport or source
execution occurs in these checks. The initial two behavioral failures remain
in `red.log`.

All 693 context tests, 35 entry-point tests and three registry checks pass.
The workspace build, Core/TUI all-target Clippy and risk gate pass; the risk
gate covers 37 changed code files. Its first sandboxed invocation stalled
before starting checks and was terminated. The normal-permission rerun passed.
Evidence is under `scripts/devex/artifacts/partial-context-generation-20261024/`.

The rebuilt native executable has SHA-256
`4356f399f5c023eac0c2bb25a961f4a7f5c1d3bfe427475137aabf5d551a0e83`.
Sequential J350 records 38 machine passes, zero failures, 39 capture pairs and
three pending operator judgments. It freezes 6,492 inputs and thirteen
programs. This rerun covers the existing partial-import journey through three
fixed local Semgrep jobs, human deferral, Report export and no-color restart.
It adds no model request. The generation regressions and native import journey
provide different evidence; this run does not qualify model-generated
architecture quality or its complete interactive generation flow.

Live model spending remains at sixteen cumulative experiment requests with no
allowance remaining. The separately prepared inventory-only scope experiment
remains unstarted. The subsequent workflow increment supplies narrow scripted
staged/refine and native generation evidence. Useful live generation, full
configuration qualification, operator UX acceptance and the five broad delivery
items remain open. No module promotion or retirement follows from this increment.
