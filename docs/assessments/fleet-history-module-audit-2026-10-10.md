# Recorded Fleet history and neutral revision comparisons

Fleet previously built its corpus from the latest finding projection. Two
observations of one identity at different recorded SHAs therefore appeared only
at the later SHA. The red regression records that loss. Ingestion now builds a
separate bounded history projection while preserving existing current-finding
rows and the authoritative per-target stores.

## Operator behavior

`fleet:diff-findings` reads the selected target and two recorded SHAs, then
reports base-only, head-only or both for uncertain source-proximity groups.
Legacy wire leads remain compatible; entries add neutral presence, match basis
and unassessed fix status. Absence cannot establish a repair or introduction.
SHA-only Fleet comparison does not distinguish dirty content, context changes
or complete scan coverage. Detailed investigation run comparison remains the
source/context/coverage reader.

Comparisons refuse more than the explicit row allowance or 8 MiB of payload.
Individual target ingestion refuses more than 10,000 observations or 8 MiB.
Missing or malformed observation payloads are honest failures. Other readable
targets survive as a partial corpus with explicit skipped-target warnings;
headless partial results use a nonzero exit code. Older corpora retain current
queries but need explicit ingestion before history comparisons.

All five Fleet tools are operational auxiliary actions. They do not produce
accepted Map evidence or additional investigation jobs. Compatible names,
headless dispatch and reference input remain. Scorecards describe records rather
than actionability; bounded finding queries show actual title, source location
and identity instead of only a row count.

## Native execution and terminal evidence

An owned Rust fixture writes four labeled synthetic observations through the
real FindingStore and two labeled SHA run summaries. Native prepared CLI
dispatch registers and updates the target, ingests it, queries current records,
reads status and compares history. Three current findings and three presence
groups remain. Blank ids, unknown keys, invalid limits, comparison overflow,
missing legacy history and skipped targets refuse honestly. Explicit ingestion
restores derived history while current-finding queries remain compatible.

Final J167:
`/tmp/kuzushi-fleet-audit-20261010/final-tui/20261010-090012/J167`.
Native SHA-256:
`bf9f4d09b8b98da07912112b2f36d2d9f83961264ec19b984d5559f3641b5a97`.
All five shell tools use actual prepared dispatch. There are 26 machine passes,
zero failures and 30 authenticated live text/ANSI captures at six viewport
sizes, complete compact comparison paging and no-color restart. Three assistant
screen judgments qualify the owned reader separately from raw REVIEW_REQUIRED
and operator approval false.

Restart preserves four observations, three current rows, neutral comparison,
unchanged owned source and zero review decisions, provider reservations or
investigation work attempts. No accepted Map baseline is manufactured. The
SHAs are labeled metadata, not actual Git commits or finding-quality evidence.

## Verification and retained failures

Twenty-one distinct focused Core tests pass with zero ignored tests: seventeen
Fleet/descriptor/reader checks, two observation-history checks and two registry
policy checks. The workspace build and risk proxy for 672 changed code files
pass, along with all ten repository summary gates. Final repository and
documentation receipts are retained under
`/tmp/kuzushi-fleet-audit-20261010`.

The first preflight expected a zero exit code for partial work; the corrected
fixture accepts the existing nonzero partial-result contract. A malformed-JSON
fixture hit SQLite's JSON index constraint before reaching the history reader;
an invalid record shape exercises that reader without weakening the schema.
The initial narrow capture sequence needed more pages to inspect both SHAs.
These failures remain retained. Two wording violations were corrected, and a
restricted-network package-manager check was rerun with approved access.

The registry fingerprint was already stale before this increment. A complete
180-tuple review retains inherited descriptor changes and the five Fleet phase
corrections. The policy invariant now permits operational writes of Kuzushi
state while preserving explicit authorization and non-operational classification
for repository execution, target writes and external actions. This policy review
does not qualify execution or usefulness of excluded capabilities.

## Remaining scope

Evidence is assigned to 64 of 109 in-scope tools; 45 remain unassigned. Fleet
maturity is unchanged. No implementation is promoted or retired. Aggregate
Fleet ingestion, registry IO, cancellation latency, concurrent scratch-file
replacement, all configurations and targetless native execution remain
unqualified. Current query totals and source coverage are not established by
bounded row results.

All nine broad delivery milestones, the complete live investigation and full
reference-product interaction acceptance remain open. No model request,
credential renewal, scanner, target-source execution, exploit development,
reproducer work, vulnerability patch, commit or push occurs. Work stays
uncommitted on main. The specific live test allowance remains pending.
