# Dependency candidate and catalog reader audit

The legacy candidate extractor is now Labs, and its successful result remains
partial even when it finds packages. On an owned mixed-manifest fixture,
`threat-intel:discover` previously reported completion with only the root npm
package. The existing SBOM reader found both that package and the nested Go
dependency. A nonempty candidate set therefore cannot establish complete
repository inventory. The audit used inert manifests and never executed source,
installed packages, queried advisories or requested a model.

Exact dispatch and existing candidate fields remain. New results and candidate
files add a coverage object. The visible summary explains incomplete coverage
and names `sbom-scan:scan` as the inventory action. Candidate extraction and
catalog reading now opt out of Map completion. No implementation was deleted.

## Individual tool evidence

| Dimension | `threat-intel:discover` | `threat-intel:list` |
| --- | --- | --- |
| Purpose | Offline package candidates for existing integrations; insufficient as the primary repository dependency inventory. | Inspect stored catalog metadata without invoking entries. |
| Phase | Auxiliary Map; a partial candidate result is not accepted context. | Auxiliary Map; reading a catalog is not accepted context. |
| Inputs | Explicit workspace, supported manifests; an optional existing context snapshot supplies technology labels. No runtime or credentials. | Workspace and optional contained catalog path. Default lookup chooses the first sorted TOML file. No runtime or credentials. |
| Execution | Real shared prepared dispatch on mixed, empty and malformed manifests, plus native headless comparison. No automatic context prerequisite executes. | Real prepared dispatch on missing, empty, malformed and nonempty catalog data. The inert entry keeps an unsupported routing label without dispatching it. |
| Outputs | Candidate JSON preserves package data and the same coverage object as the result. SBOM comparison finds the omitted child dependency. | Result preserves entry identity and metadata. The native summary is a count, not a dedicated catalog browser. |
| Failure | Malformed input fails without replacing previous candidates; symlinked manifest and unknown option are refused. | Missing or malformed documents fail; an explicit outside-workspace path is refused. |
| Resources | Zero provider requests. Per-file input cap 8 MiB, output cap 16 MiB. Aggregate inspection and in-flight cancellation remain unqualified. | Catalog read cap 8 MiB. Default directory enumeration has no entry cap and skips unreadable entries. |
| Scope | Root npm/Cargo/Python files; child Go inspection occurs only when root collection is empty. Bazel traversal stops at depth 12 or 10000 entries without a complete skipped-path ledger. Empty subtrees may read enclosing Bazel manifests. | Shared prepared input confines explicit catalog paths. Default lookup is local but does not ask the operator to select among multiple catalogs. |
| Interfaces | Exact run and shell dispatch remain; default discovery omits the Labs tool. No SAST engine or scan-mode qualification. | Run and shell reader behavior use the same prepared executor. No scan-mode engine qualification. |
| Value | Legacy integration compatibility is retained. The observed coverage and scope limitations prevent Core qualification. | Core retained for narrow metadata reading; no finding verdict, source applicability or security effectiveness claim. |

The collector's root-only manifest rules, conditional child lookup, enclosing
Bazel behavior and missing aggregate budget are disclosed rather than expanded.
The SBOM alternative also has recorded limits in its
[separate assessment](sbom-inventory-audit-2026-10-10.md). Neither tool can claim
complete dependency coverage on arbitrary repositories from this small fixture.

## Verification

Eight new prepared-dispatch tests and ten existing candidate-input tests pass.
The workspace build passes. Six focused TUI notice tests also pass. This increment qualifies
only these local inventory and reader behaviors; external research, catalog
application, harvesting and discovery engines were not exercised.

Evidence is retained under
`/tmp/kuzushi-tui-integration-20261012/dependency-candidate-audit` and
`/tmp/kuzushi-tui-integration-20261012/dependency-candidate-tui`.
The native bundle SHA-256 is
`4c92bc6e85854452b61c7487a0305869797f615543b7e33abe484c3de706c483`.
No broad delivery milestone or reference-product parity claim is closed.

The first native passes exposed an input-ordering defect: the Replay footer
advertised warning dismissal, but Escape restored the previous view before
clearing the warning. Contextual readers now dismiss warning/error notices
first and preserve their navigation origin. The next Escape returns. Completion
notices still clear while allowing Back. Focused tests cover Replay, Trace, Run
Diff, Scene and Jobs alongside the existing embedded trace checks.

Final J226 records 18 machine passes, zero failures and 20 live capture sets
across six terminal sizes and no-color restart. It executes the real candidate,
catalog and SBOM tools. The candidate receipt stays partial; the SBOM receipt
contains both fixture dependencies. No phase attempt, finding, review decision,
investigation job or provider reservation is created. Source hashes are unchanged.
Restart visibly reopens the original partial receipt and its coverage warning.

Assistant capture review found the outcome and recovery action readable. At
40x12, one Page Down reaches the complete warning and inventory command;
Escape now dismisses the warning while preserving Replay, then advertises Back.
Long paths and protocol metadata still occupy substantial space. Catalog results
remain count-oriented. These are not product-parity or complete investigation
acceptance claims. Both human review items remain open, with
`operatorApproved: false` and the raw `REVIEW_REQUIRED` verdict retained.

The final journey is retained at
`/tmp/kuzushi-tui-integration-20261012/dependency-candidate-verified-tui/20261013-031005/J226`.
Earlier failed journeys remain available: one expected an unused prerequisite
dialog, another captured Replay before loading and expected Setup on restart,
and a third reproduced the Escape defect. None is counted as a successful run.
