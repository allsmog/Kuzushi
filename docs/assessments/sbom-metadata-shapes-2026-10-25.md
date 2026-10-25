# Dependency metadata validation and recovery

Five real prepared CLI probes exposed a false-success case in the Core
`sbom-scan:scan` inventory. A `package.json` containing `[]`, a dependency
section containing an array or null, and a numeric dependency specification
all completed. The numeric entry produced an edge without a component.
These were unsupported inputs, not evidence of an empty dependency inventory.

Components and edges now share one parser for the supported package shapes.
The document and any present dependency sections must be objects. Entries
must have a string specification or the existing compatibility object with a
string `version`. Empty strings, aliases, URLs, Git and local specifications
remain accepted without installation or resolution. npm documents its standard
dependency maps and string specifications in the
[package.json reference](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/).
The object form is Kuzushi compatibility behavior, not an npm schema claim.

Errors identify the relative manifest and field without dumping an unsupported
value. One unsupported nested manifest fails the operation without publishing
parent packages, edges, CycloneDX or SPDX. Available capture hashes and byte
inspection remain in the failed result. Existing stored results are unchanged.
The Components reader clears stale package claims and now directs the operator
to check the reported file or limit before an explicit rerun.

## Functional evidence

The current production cut passes 89 focused Core SBOM checks and 37 TUI
component checks, Core and TUI all-target Clippy, and the workspace build.
Seven new Rust checks cover shape failures, preserved string and compatibility
forms, matching component/edge membership, nested failure and correction.
The original failing regression remains recorded. Final summary and risk
results are recorded separately with an unsigned draft receipt. Publication
requires clean final-head verification and a signed receipt.

The five headless probes now return exit 0 for supported metadata and exit 3
for each unsupported shape. Each durable `done.json` agrees with the process
and result status. Their source bytes remain unchanged. Failed output contains
no package claims. The supported probe retains its component and edge.

Existing component regressions also confirm that a failed result clears stale
data, a foreign-target result is ignored, and late target inspection cannot
overwrite an explicit tool result. Source inspection found the shell already
blocks a second active tool. No speculative ordering layer was added.

## Tmux and visual review

Final J364 records **39 machine passes, zero failures, 32 live capture pairs
and three pending formal operator judgments**. Raw exit 4 remains
`REVIEW_REQUIRED`. The agent answered all three questions using State, Intent,
Honesty and Craft and inspected sixteen ANSI cell replays. These use Menlo and
a chosen default background; they are not OS screenshots or parity evidence.

The owned fixture first inventories three declared packages from two manifests.
An explicit fixture edit makes the child dependency section unsupported. The
next run fails and Components removes the old package claims. After a separate
source correction and rerun, all three packages return. No-color restart
recollects them while retaining exactly two completed runs and one failed run.
Both successful results contain three packages in CycloneDX and SPDX.

Captures cover 40x12, 60x20, 80x24, 96x89, 120x36 and 160x48. Narrow paging
reaches the full error, recovery commands and all package specifications.
No-color has no color SGR codes; bold, dim and reverse attributes remain.
Independent checks confirm capture provenance and the frozen native hash.
The duplicate bottom-page PNGs are identical, not missing terminal content.

The first J364 attempt has 17 machine passes and one retained failure: its new
page helper skipped the initial narrow frame containing the path. The helper
now includes that frame. This was not a product path truncation. The first
screen review also led to the clearer file-or-limit recovery hint.

## Evidence and limits

Local root: `scripts/devex/artifacts/sbom-contracts-20261025/`. The original
headless results are under `attempt-2/`; corrected probes are in
`repair/headless/`. Rust, lint and build logs are under `repair/`. The final
native run, independent checks, agent answers and images are under
`native-attempt-2/`. Thirteen frozen programs and 6,603 repository inputs remain
unchanged during that run. Subsequent documentation updates are recorded
separately.

Native SHA-256:
`873fc2680cd9233b8a3f626b4bb15a19b1fcffe0fb8dbb519f949df39867f5a7`.

No model, credentials, target-source execution or package installation is
required. There are zero provider reservations, findings, phase attempts,
campaign plans or discovery jobs. This does not qualify an authenticated Git
snapshot, complete npm validation, dependency resolution, every ecosystem,
general detector usefulness or reference-level UX. The module stays auxiliary
Core Map. Four broad delivery items retain local acceptance and five stay open.
