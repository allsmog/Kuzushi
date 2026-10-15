# Report source summaries and format disclosure

Report exports now preserve the recorded source summaries supplied by the
finding projection. JSON and JSONL add optional `provenance.sourceHistory`,
SARIF adds `kuzushiSourceHistory` to result properties, and Markdown manifest
entries add `sourceHistory`. Markdown displays eight summaries at most and
points to the manifest for the remainder. Dates and first/latest run references
stay associated. These are source summaries, not a complete raw observation log
or evidence that a finding applies at another commit.

Export evidence counts and the shared Review evidence label use the finding
domain's distinct producer/signature count. Repeated passes remain visible
without becoming independent corroboration or changing confidence. Canonical
Report reads the shared format omission contract and discloses whether source
summaries survive the selected export. CSV explicitly omits the history; the
external scanner format retains its existing provenance omission. No new tool
options, stored finding formats or automatic work are introduced. Rust literal
callers have an additive field migration documented in RELEASING.md.

## Regression evidence

The repeat-run projection regression fails before repair and passes afterward.
The workspace test filter passes 765 tests with two ignored; the Report summary,
export preview and Review state filters pass 4, 9 and 18 respectively. Together
these are 795 distinct passing tests. One preview test overlaps the Review state
filter and is counted once. The initial CSV test exposed an older assertion that
omitted previously added review-basis and lesson disclosures.
It now checks the complete shared omission list and requires the history omission.
Workspace build and the 157-file production risk proxy pass. All ten repository
summary gates pass. The unsigned receipt is
`/tmp/kuzushi-report-history-20261011/precommit-verify-receipt.json`; its dirty
and drifted state cannot attest to a clean commit. Existing upstream terminal
code still emits its known parentheses warning.

## Native evidence

Final J189 is
`/tmp/kuzushi-report-history-20261011/corrected-native/20261011-002116/J189`.
It has 11 machine passes, zero failures and 14 authenticated native text/ANSI
captures across six terminal sizes and a no-color restart. Native SHA-256 is
`0bf82fce156b68d7c00426e4075fa34107b1f8f837561b5311c0137006e37987`.
Requested and actual dimensions match in every capture. The selected JSON format
survives restart; switching to CSV shows the omission before export. At 40x12,
the second PageUp from the bottom reaches the complete history disclosure.
Compact chrome is still dense and one composer hint is clipped at that size.
One scoped assistant judgment is recorded separately from the raw
REVIEW_REQUIRED result and operator approval false.

The first journey failed because its generic Navigate helper left Report for
Review. The helper was removed from this journey, and the format step now starts
from the actual saved JSON choice. No product input behavior was changed to make
that test pass. Both failed and corrected runs remain in the evidence root.

The existing owned fixture exports its same three source summaries through all
four rich formats, reporting one distinct source and preserving the human
false-positive decision's recorded SHA
`f29dc288e0660ad20d074fc219c025f98ef7d155`. Source and owner configuration are
unchanged. The ledger remains at four provider reservations, six work attempts,
three observations and one human decision. There are no new model requests,
scans, source execution, allowance approvals or queued follow-ups. Historical
real-provider results do not establish new Review adapter validation.

## Remaining acceptance

Live Review remains pending its specific proposed allowance and launch approval.
Complete per-tool readiness, calibrated Review usefulness, cancellation and
exhausted allowance, source drift during active work, physical/operator screen
acceptance and full reference parity remain open. No module is promoted,
retired or deleted. All nine broad delivery milestones remain unchecked.
