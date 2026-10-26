# Source-qualified SPDX exports

The captured repository dependency metadata produced 285 SPDX package records
with 30 duplicate identifiers and 13 relationships referencing undefined
elements. Its document also failed the released SPDX 2.3 JSON schema with 857
missing-date errors. The exporter identified packages by sanitized name and
ecosystem, while its relationship lookup discarded source and version context.

## Correction and compatibility

Package identifiers now derive from the complete recorded component identity:
ecosystem, name, version, source path, scope and package URL. Identical records
share one exported package; the canonical inventory retains every original row.
Identifiers stay stable when record order changes. Each generated document has
a fresh namespace, UTC creation and annotation dates, and explicit package
descriptions. These identify export records, not a Git revision, installed
dependency state or an atomic source snapshot.

Relationship candidates come only from the edge's recorded source. An endpoint
must identify exactly one package. Ambiguous versions, missing components and
the overloaded `root` name produce explicit omissions instead of guessed links.
`data.spdxExport` retains each omitted edge and its candidate identifiers. The
standalone document includes omission annotations, and operator output names
the omitted count. Raw components and dependency edges remain unchanged.

The [SPDX package identifier rules](https://spdx.github.io/spdx-spec/v2.3.1/package-information/#72-package-spdx-identifier-field)
require distinct references for package elements. The
[document namespace rules](https://spdx.github.io/spdx-spec/v2.3.1/document-creation-information/#65-spdx-document-namespace-field)
distinguish generated document versions. Consumers must join actual `SPDXID`
values rather than reconstructing the former name-based value. See the
[migration notes](../../RELEASING.md#source-qualified-spdx-package-references).
Saved exports and public report structs retain their existing contracts.

## Actual metadata probe

The probe reads the same owned two-file copy used in the pnpm audit. Both source
hashes, all 285 canonical components and all 427 raw dependency links remain
unchanged. No package installation or target program runs.

| Check | Before | Corrected |
| --- | ---: | ---: |
| Package records | 285 | 285 |
| Distinct package identifiers | 255 | 285 |
| Undefined relationship references | 13 | 0 |
| JSON schema errors | 857 | 0 |
| Explicitly described packages | 0 | 285 |
| Exported dependency relationships | 427 | 384 |
| Disclosed omitted raw links | 0 | 43 |

Thirty omitted edges have ambiguous endpoints; thirteen have missing
components. Every raw link remains available for later refinement. This does
not establish version-specific resolution for the name-level graph.

Validation uses the
[official SPDX 2.3 schema at its release commit](https://raw.githubusercontent.com/spdx/spdx-spec/aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json)
and the already installed Ajv 8.20.0. Separate checks verify identifier
uniqueness, reference closure and package descriptions. Schema validity is
scoped evidence, not complete semantic or ecosystem conformance.

## Shared dispatch and terminal verification

Nine export contract checks, nine inventory integration checks, eighty existing
engine checks and eight adapter checks pass: 106 distinct focused Rust checks.
Core all-target Clippy, the workspace build and the risk proxy pass. Final
repository summary evidence is recorded separately with this draft.

The first native run exposed a real adapter defect: adding inspection text
rebuilt the summary and removed the export warning. A new prepared-dispatch
regression fails before correction and passes afterward. The adapter now keeps
the complete export summary before appending its resource receipt.

Final sequential J371 records **25 machine passes, zero failures and 28 live
capture pairs**, with thirteen programs and 6,679 source inputs unchanged during
execution. Native SHA-256:
`5219011b37bfb0520ae9ba139b22fb040d0cc7ab7c802f13305ceacd0fde5e39`.

The owned inert fixture retains five component records and five raw edges while
exporting two dependency relationships and disclosing three omissions. The
complete warning fits one expanded 40-column viewport. Components and restart
retain the original receipt without manufacturing findings or phase progress.
Captures cover 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48. All 28 declare
no-color and contain zero color SGR codes. Eight inspected PNGs replay captured
ANSI cells with Menlo and a chosen background; they are not OS screenshots.
Both questions have State, Intent, Honesty and Craft answers. Raw exit 4 remains
`REVIEW_REQUIRED` with two formal operator judgments pending.

Earlier runs retain the missing warning, insufficient compact paging and an
assertion that did not remove display prefixes. The fourth has 25 machine
passes and monochrome streams, but its restart metadata says `default`; the
fifth explicitly declares no-color again. These results keep their own source
cuts and are not reassigned to the final run.

Local evidence: `scripts/devex/artifacts/sbom-spdx-20261025/`. It contains the
schema revision and digest, red and green checks, actual before/final results,
the unchanged raw-data comparison and all five native attempts. The final
attempt contains provenance checks, question answers and cell replays.
Subsequent documentation updates are separate from frozen product inputs.

No live provider request, allowance, source execution or maturity change is
added. The sixteen-request live experiment allowance remains exhausted.
Authenticated Git freshness, full ecosystem and semantic conformance,
CycloneDX correctness and reference-level UX remain open. Compact log density,
diagnostic chrome and singular lockfile wording remain polish gaps. No broad
delivery checkbox closes.
