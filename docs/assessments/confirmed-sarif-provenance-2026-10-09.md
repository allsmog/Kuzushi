# Confirmed report provenance, October 9, 2026

The confirmed SARIF exporter could omit a human-confirmed finding after a new
observation of the same identity. It selected confirmed observation row ids,
while the workspace reader selected the canonical effective review across
observations. A shared-dispatch test reproduced the mismatch: the workspace
projection retained the human confirmation and source-change warning, but the
confirmed export had no results.

## Changes

Shared `report:sarif` dispatch now consumes the same enriched review records as
workspace exports. The common reader preserves decision authority, reason,
source basis, relationships and reviewed lessons. A later human false-positive
decision still reverses confirmation. Managed rule suppression remains a
separate property. Exporting does not rewrite observations or decisions.

Run properties identify investigation versus workspace-history scope. Result
properties retain the recorded decision basis and distinguish comparison of
recorded observations from current-checkout applicability. The latter is
explicitly `not_assessed`; unavailable source evidence remains unknown. The
owned fixture has actual captured source content but no Git revision metadata,
so its TUI honestly names revision metadata as unreadable. This experiment does
not establish current-SHA applicability or finding validity.

The public `ConfirmedSarifSelection` interface remains compatible. Callers
without workspace metadata keep the legacy row-id selection and unknown source
metadata. Shared dispatch uses canonical identity review. Output containment,
explicit target-write approval, atomic writing, study selection and matrix
receipts remain in the existing dispatch and reporting paths.

## TUI changes

A focused regression found that a successful tool without an Activity timing
record emitted no completion notice. Completion now announces itself without
inventing duration or changing the operator draft or view. Known duration and
completion after cancellation retain their distinctions. Native Run Focus
already replaces the generic tool banner with its durable run receipt; the
journey checks that actual receipt separately.

The previous credential assessment found Setup's Enter hint clipped at 40
columns. Picker guidance now uses a compact form at narrow widths that preserves
movement, Enter selection and command entry. It keeps the same input ownership
and wide-terminal guidance. The credential journey verifies the actual hint.

## Verification

Evidence root: `/tmp/kuzushi-confirmed-sarif-20261009`.

- Ten confirmed-report tests cover canonical confirmation after source change,
  later human reversal, compatibility output, independent suppression, unknown
  source, empty output, unsupported input, missing store, hostile finding text
  and output containment.
- Fifteen investigation-report consumers preserve selected-study and matrix
  membership, receipts, historical boundaries and refusal before publication.
- Twelve export projection, twenty-four workspace SARIF and nine decision-basis
  regressions protect the shared enrichment extraction.
- Twenty-four tool completion/persistence tests and six prompt rendering tests
  pass. The new prompt check renders a real 40-column terminal buffer.
- The native debug binary builds, and all ten quick summary gates pass in
  `verify-final.json`. These local quick checks do not establish full CI or
  cross-platform acceptance.

The initial completed J139 is
`/tmp/kuzushi-confirmed-sarif-20261009/tui/20261009-041137/J139`.
It records twelve machine passes, no failures, four human questions and
twenty-four authenticated live capture pairs. All six sizes and seven no-color
captures are present. No-color output contains no color SGR sequences; bold,
dim, inverse and reset SGR remain. Native SHA-256:
`15b9662d9591c64bb49c1ef4d22b3bdd416612a3a9533f5c1775b9798b401b7f`.

The fixture uses two labeled observations over comment-only owned source and
one human decision. Both native run and interactive shell export exactly one
recorded confirmation with the earlier decision source and later observation.
The shell writes no report before explicit approval. The fixture checks both
documents, unchanged source, two observations, one decision and zero provider
reservations or work attempts after export and restart. No scanner, provider
request or source execution occurs.

At 40x12, five real detail pages reach the decision, source-change warning and
both observation references. `q` returns to the finding list. The transient
completion notice can temporarily consume the tiny list body, and the Prompt
footer still truncates its long navigation hint. The operator can enter
Navigate, dismiss the notice, open the finding and page it, but this remains a
partial comfort judgment. Three scoped judgments pass and one remains partial.
Raw `REVIEW_REQUIRED` and operator approval false remain explicit.

## Retained failures and limits

Retained failures include a fixture missing its initial run, the real row-id
selection defect, a test module incorrectly scored as production, a reversal
test using the wrong enum spelling, and fixture expectations for output refusal,
generic completion wording and a zoom heading omitted at the smallest viewport.
The no-Activity completion regression also failed before the production fix.
Two export test filters initially selected zero tests; only the corrected
twelve- and twenty-four-test runs are credited. No gate was relaxed and the
journey driver was not changed.

This provides scoped report and management evidence. Full SARIF schema and
external consumer interoperability, all options, large-ledger cancellation,
current-checkout applicability, full TUI parity, the remaining module audit and
the complete real-model investigation remain open. No module maturity or full
delivery milestone is promoted. Work remains uncommitted on main.

## Compact notice follow-up

The initial screen review found a passive receipt hiding the entire finding
list at 40x12. A real terminal-buffer test reproduced that blank body. Passive
notices now use one row at twelve or fewer terminal rows and keep the existing
route to the complete message. Warnings and errors preserve their longer
preview, Escape dismissal and complete-message route. Finding identity and
count stay visible; a very small viewport can still require opening the detail
to read its title. Two focused buffer regressions pass, alongside the existing
section-slot and notice-banner tests. The first test originally required the
full title; only identity fits alongside the retained chrome, so the final
claim and assertion are explicitly limited to identity and count.

The completed compact-notice J139 is
`/tmp/kuzushi-confirmed-sarif-20261009/tui/20261009-042127/J139`.
It records thirteen machine passes, no failures and twenty-four authenticated
live capture pairs, including seven no-color frames. Source, ledger, report and
paging checks remain intact. Native SHA-256:
`3ae2d160ccf9f6c0fdcf61b4f0b1fa66130334936b1a857132bebc0cf577cbec`.
The separate scoped review keeps three passes and one partial for tiny viewport
reading comfort and the truncated Prompt navigation hint. Raw REVIEW_REQUIRED
and operator approval false remain explicit. Final summary verification is
recorded in `verify-notice.json`; the earlier green receipt remains separately
retained.

Final verification includes 112 focused checks, a locked workspace build and
all ten quick gates. The final documentation-only check and workspace build
logs are `docs-shipping.log` and `workspace-build.log` in the evidence root.

The workspace build produced a different executable hash, so J139 was rerun
against that exact artifact. Final J139 is
`/tmp/kuzushi-confirmed-sarif-20261009/tui/20261009-042918/J139`:
thirteen machine passes, no failures, twenty-four authenticated live captures,
seven no-color captures and the same three passing/one partial scoped review.
Every capture matches the current executable SHA-256:
`6f404cf9144a139510b90b9b0f0925358bbe7ceec3ba0cb1ad6b80b257b01bc7`.
Recovery again retains unchanged source, two observations, one decision and both
reports, with no provider or scanner work. Earlier receipts remain intact.
