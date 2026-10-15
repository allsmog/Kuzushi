# Source-bound triage and historical reading

This increment audits `triage:run` standard classification through shared
prepared dispatch and follows its stored output through Review, Report and
restart. It uses an owned inert Markdown file and explicitly labeled synthetic
review outcomes. No provider request or target source execution occurs.

## Confirmed defects and repairs

The standard runtime cache previously matched model, directory, fingerprint
and selected prompt fields without binding the inspected source. A prepared
dispatch regression changed the source between two observations of the same
finding. It expected two runtime calls but observed one before the repair.
The before-fix log is preserved at
`/tmp/kuzushi-triage-source-audit-20261010/prepared-before.log`.

Reuse now binds the captured source snapshot, complete serialized review
request and a specific runtime attestation of triage defaults and translation.
Missing source identity or attestation disables reuse. Current external
adapters do not attest this path and therefore execute live. The additive
runtime method defaults to `None`; tracing and runtime handles forward explicit
attestations. Retriage bypasses reuse. Failed or incomplete runs discard
entries for their snapshot, including a prepared review whose source changes
during execution. The cache remains bounded to 4,096 outcomes.

The native experiment also exposed an exact-generation reader defect. An old
observation requested an anchor in the current folded list, where that
observation no longer appeared. Refresh failed and retained the newer reader.
An exact `generation:<id>` now opens its pinned reader without a folded-page
request. The existing list page, historical-selection disclosure and decision
guards remain intact. Ordinary alias opens retain their page behavior.

## Phase and artifact evidence

The fixture records two source observations and executes two standard reviews
through descriptor validation and prepared dispatch. Each review selects its
explicit `scanId`, disables prefiltering and identity reconciliation, and
persists an automated needs-review outcome. Both results are completed and
carry different source snapshot hashes. Their fixed test runtime reads the
owned file; this proves adapter invocation and source isolation, not model
judgment quality.

Native Review shows the newly produced rationale, then opens the earlier
generation with its original rationale and changed-source disclosure. Returning
to the newer generation restores its own outcome. A scripted human deferral
adds a third durable decision. SARIF retains the finding and deferral; a fresh
no-color shell reads the same human decision. The ledger retains two raw
observations, two automated decisions and one human decision. Reading, export
and restart leave the four existing observation/review result receipts intact.
No additional tool or provider work starts.

## Verification and terminal evidence

182 distinct focused Rust checks pass across triage-related contracts,
finding paging and ordinary reference opens. Two explicit paging-fixture tests
remain ignored. Workspace build passes. The changed-code risk gate passes for
111 files, including the previously staged work and authenticated dependency
baseline. All ten repository summary gates pass. The unsigned receipt is
`/tmp/kuzushi-triage-source-audit-20261010/precommit-verify-receipt.json`.
It records dirty/drifted state and cannot attest to a clean commit.

Final J184 is at
`/tmp/kuzushi-triage-source-audit-20261010/complete-reading/20261010-205224/J184`.
It records 16 machine passes, zero failures and 20 authenticated native
text/ANSI captures. Native SHA-256 is
`4da502b475eab0ab3351d3796627b01c317ad06ae02981030b391f8340fd85ae`.
Captures cover 40×12, 60×20, 80×24, 96×89, 120×36 and 160×48, plus no-color
restart. At 40×12, visible paging reaches rationale, observation provenance,
missing-commit disclosure, source excerpt and the empty evidence state.
The compact reader remains dense and requires repeated paging.

Assistant judgments are saved separately in `assistant-judgments.json` in that
evidence directory. Raw status remains REVIEW_REQUIRED and operator approval
remains false. These judgments cover the owned fixture, not complete product
acceptance or terminal-reference parity.

Earlier runs remain preserved under the same evidence root. The first used
incorrect small generation IDs. The second used actual IDs and exposed the
folded-anchor defect. The third verified the reader repair but its helper
incorrectly expected JSON while the product exported default SARIF. The
following run completed but captured only part of compact provenance; the final
run extends that reading evidence. Helpers and journeys were changed only after
their processes finished.

## Remaining qualification

This is scoped standard-strategy evidence. Deep and gate-deep behavior,
live-model usefulness, calibrated verdicts, all declared options, durable
allowance enforcement, retries, cancellation timing, concurrency and complete
scan/shell/run parity remain unqualified here. DAG dependency labels receive
no execution-ordering credit. No maturity downgrade or module removal follows.

This fixture has no Git commit. Its content snapshots differ, but it cannot
establish SHA comparison behavior. Historical decision provenance in its pinned
reader is disclosed as absent; the original rationale and captured source
excerpt remain readable. It does not establish that a finding was fixed, or
authorize carrying an old verdict onto a different revision. The earlier live
source-revision assessment remains the separate evidence for exact Git history.
The legacy standard-response stage label also remains a compatibility/copy gap;
it does not establish that a different selected model ran.
