# Source-qualified dependency exports

The same captured metadata used in the SPDX audit exposed a second defect:
285 CycloneDX components had only 284 distinct references and thirteen links
pointed to undeclared components. Its name-only lookup could also redirect a
manifest edge to a different source or version. JSON schema validity alone
did not detect these defects.

## Shared graph and honest completeness

Both formatters now consume one in-memory graph derived from the captured
report. Component identity includes ecosystem, name, version, source path,
scope and package URL. Only unique candidates from the edge's recorded source
produce relationships. Missing or ambiguous endpoints retain their raw edge
and candidate references as omissions. Rendering adds no source traversal.

SPDX retains its corrected identifiers and relationships. CycloneDX uses opaque
record references while preserving package URLs as metadata. Identical records
share an exported component without changing the canonical inventory. Both
formats publish one combined omission warning instead of duplicate messages.
Consumers must join actual reference fields; see the
[compatibility notes](../../RELEASING.md#source-qualified-cyclonedx-references).

The [released CycloneDX 1.5 schema](https://raw.githubusercontent.com/CycloneDX/specification/87bf83aa73cb3b1755ddd3d89f144353ab7beaf6/schema/bom-1.5.schema.json)
requires distinct references and describes compositions for dependency
completeness. The exporter marks observed mapping gaps `incomplete` and
otherwise leaves completeness `unknown`. It does not manufacture empty leaf
records from missing outgoing evidence. Compositions explicitly reference all
recorded components and the root. Standalone metadata retains omission details;
`data.cycloneDxExport` exposes the same evidence with counts. Fresh serial
numbers identify documents, not authenticated Git revisions or installed state.

## Captured metadata comparison

The plain native probe uses the same owned two-file target, explicit 4 MiB
per-file and 8 MiB aggregate limits, and isolated credentials. Both source
hashes, all canonical records, raw links and capture-inspection fields remain
unchanged. No target package script or installation runs.

| Check | Before | Corrected |
| --- | ---: | ---: |
| Canonical component records | 285 | 285 |
| Distinct CycloneDX references | 284 | 285 |
| Undefined dependency targets | 13 | 0 |
| Raw dependency links retained | 427 | 427 |
| Exported dependency relationships | 406 | 384 |
| Explicit omissions | 0 | 43 |

An independent metadata join matches all 285 exported records to the canonical
inventory without recomputing the implementation's hashes. It reconciles all
384 source-qualified reference pairs and all 43 omission candidate sets. The
earlier SPDX identifier set and relationship array remain exactly unchanged.
The old graph's 406 links included guesses and collapsed source distinctions;
its count was not a coverage or precision measure.

Validation uses the official `1.5.1` release commit's three pinned schemas,
already installed Ajv 8.20.0 and `ajv-formats`. Structural schema validation
passes before and after; independent uniqueness, reference-closure and source
membership checks detect the actual defects. Sixteen retained compilation
warnings concern unsupported `iri-reference` and `idn-email` formats. This
exporter emits no contacts or external BOM links, but those warnings prevent a
claim of complete format validation. Package URL semantics and general
ecosystem fidelity also remain unqualified. No validation package is installed.

## Tests and native operator path

All seven new regressions fail before correction. Twenty-five focused export
and prepared-inventory integration checks, eighty engine checks and eight
adapter checks pass: **113 distinct Core checks**. Core all-target Clippy,
workspace build and the risk proxy pass. Final repository summary evidence is
recorded separately with this draft.

Sequential J372 records **25 machine passes, zero failures and 27 authenticated
live capture pairs**. Thirteen programs and 6,683 source inputs remain unchanged
during execution. Native SHA-256:
`09b59ec0f54f37b00eb0409e13f963a22e9030ac14c7ad5ae076b7f43ec231eb`.

The owned inert fixture retains five records and five raw links. Each format
maps two relationships and discloses three omissions. The combined warning
fits one expanded 40-column viewport. Components retains two declared
constraints and three observed versions. Explicit no-color restart preserves
the original result with no model call, finding, investigation job or phase
completion. Captures cover 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48;
all 27 declare no-color and have zero color SGR codes.

Eight inspected PNGs replay ANSI cells using Menlo and a chosen background;
they are not OS screenshots. Both questions have State, Intent, Honesty and
Craft answers and explicit `PASS_WITH_FINDINGS` review verdicts. The raw harness
exit 4 remains `REVIEW_REQUIRED`; it is not rewritten as a machine pass. The
audit skill assigns these judgments to the reviewer and requires no separate
operator approval for each screen. Compact density, diagnostic chrome, singular
lockfile wording and overall reference-level UX remain open.

Local evidence: `scripts/devex/artifacts/sbom-cyclonedx-20261026/` contains
schema hashes, red and green checks, actual before/after results, the independent
record join and native proof. Subsequent documentation updates are separate
from frozen production and test inputs. The earlier 33-file staged checkpoint
is untouched. This followup supersedes parts of the separately archived,
unapproved SPDX draft; it does not rewrite that draft's evidence.

No live provider request, allowance expansion, source execution, module
promotion or broad delivery closure follows. The sixteen-request live test
allowance remains exhausted. Full semantic conformance, authenticated source
identity, all interfaces, model usefulness and general operator acceptance
remain open.
