# Matrix reports and operator control

Matrix reports now rebuild evidence from the approved fixed plan, authenticated
attempt receipts, the findings ledger and human decisions. Each context retains
its own conditions and recurrence denominator. Work totals count jobs; finding
totals count distinct ledger projections. Neither combines recurrence across
contexts or raises confidence.

The additive `InvestigationReportDocument` API supports single studies and
context matrices. Existing single-study constructors and readers remain
compatible. Matrix consumers use the document reader explicitly. Shared
approval checks authenticate plan digest, workload, source, configuration and
every approved job input. Historical reports retain their original source after
the files change. Unapproved or changed plans cannot assert approved work.

JSON, JSONL and SARIF embed the report receipt. CSV and external scanner row
formats retain their contracts through sidecars. Markdown bundles include the
receipt and per-case work summary. Confirmed-only SARIF retains its decision
filter while supporting a matrix campaign.

## TUI behavior

`R` from matrix results opens Report for the exact saved plan. A background
reader checks its digest. Missing, changed or foreign evidence cannot silently
become a workspace-history export. Reopening refreshes decisions and outcomes;
Esc restores the selected case and composer draft. Reading and comparing start
no jobs or model requests.

Reports name recorded source and explicitly disclose unverified current-source
applicability. Per-case source/context references are available in `p` details.
Selected export format, completeness and destination remain visible while
paging. Old informational navigation hints clear on entry; warnings and errors
remain. Keyboard paging retains the full document at narrow sizes.

## Verification and limits

The final native J110 evidence is
`/tmp/kuzushi-matrix-report-20261007/tui/20261007-155416/J110`:
24 machine passes, no failures, five passing audit judgments and 25 captures
across six viewport sizes and no-color restart. Raw `REVIEW_REQUIRED` and exit 4
remain unchanged; `manual-review.json` records the separate judgments.

This is an archive-consumption test using copied, labeled synthetic receipts.
It starts no scans, executes no target source and makes no new model requests.
The report retains six observations, one distinct finding, a human false-positive
decision and Alpha 3/3, Beta 2/3 and Gamma 1/3 recurrence. The scoped JSON and
sidecar agree. Nine settled calls, nine attempts and protected review two remain
unchanged under the existing eleven-call allowance. Source bytes and the active
context mirror remain unchanged.

The first J110 run passed its machine checks but exposed poor export-selection
feedback and a stale navigation notice at 40×12. Its raw captures and failing
audit judgment remain at `20261007-153259/J110`. The final run verifies both fixes.

Focused checks pass: twelve core report tests, thirteen matrix interaction tests
before the presentation refinement, and 152 TUI tests selected by `report`,
including the final navigation and persistent-selection tests. Workspace build,
the CRAP-risk gate and all ten quick verification gates pass. Receipts disclose
the dirty working tree and do not certify a clean commit. Final capture code
identity stayed unchanged. Captured native SHA-256:
`11355f32d7ecad87924977e1cd8f75a9c14e9aa0cd37518c886b3894d8d0e9f6`.

The actual live-model ledger remains at seven settled requests and five attempts;
this increment adds none. Live-model accuracy, complete phase acceptance, all
scanner adapters and visual parity with the reference applications remain
unproven. All nine delivery milestones remain open.

## Next work

Matrix studies still need a dependable automatic handoff into the existing
durable Scan acceptance journey. The explicit report action is available without
forging phase completion. Add evidence for exhausted allowance, partial jobs,
cancellation, source drift and restarted failure recovery. Review report-cache
cost on large ledgers and protect export selection against concurrent replacement
of an already-approved plan. Case label editing and clearer case/pass job labels
also remain. Continue the registry-derived functional audit, monorepo scope review
and reviewed learning work without speculative module deletion or automatic
follow-up jobs.
