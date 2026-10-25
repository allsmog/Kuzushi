# Evidence origins agree across Review and Report

Two conversions overstated evidence. Imported reasoning could display as
model-generated despite making no model request. Export classification also
counted an explicit unscored model claim as observed code or capture evidence
when it contained a filepath or capture reference. The
[diagram-link inspection](dfd-literal-links-2026-10-25.md) exposed the initial
label gap; inspecting the downstream exporter found the second defect.

The TUI and export projections now share a pure findings-domain origin class
and presentation label. Generic `reasoning` becomes `reasoning assertion`;
explicit `model-claim-unscored` remains model reasoning. Both classes remain
excluded from observed code and capture counts. The compatibility predicate
continues to protect these reasoning kinds from observed-source proof. Existing
findings, confidence values, source identities and human decisions are preserved.

JSON/JSONL add `reasoningAssertionCount`; SARIF and bundle manifests expose the
matching counts. CSV appends its new column after all existing columns. Generic
reasoning no longer establishes model authorship or automated reasoning, and a
reasoning-only record uses state `reasoning_assertion`. The
[migration notes](../../RELEASING.md#evidence-origin-classification-in-reports)
cover strict state consumers, the public Rust summary field and older exports.
No finding-store migration is required.

## Validation

The first meaningful regression imports an owned informational row through the
real importer, loads its stored projection and renders selected detail plus
plain output at forty and 120 columns. It reproduces the invented model-origin
label and now checks `needs_review`, unverified runtime status and unchanged
serialized stored findings. Additional cases preserve explicit model claims,
source/capture labels and existing zero-confidence semantics.

Two export regressions then reproduce invented authorship and the promotion of
an explicit model claim carrying source or capture fields. The completed tests
exercise shared classification and the actual export projection, including
non-observed counts and recorded automated reasoning.

There are 940 distinct passing Rust checks: 884 workspace/export tests, one
existing evidence-kind contract, 51 findings view-model checks and four Review
navigation/rendering checks. Two manual probes are intentionally ignored: native
matrix receipt generation and inventory throughput. Core/TUI all-target Clippy,
workspace build and the changed-code risk proxy pass. This macOS run does not
qualify the wider platform matrix.

Final native J362 records 23 machine passes, zero failures, nineteen capture
pairs and four pending formal operator judgments. Raw exit 4 remains
`REVIEW_REQUIRED`. Four separate agent answers and ten inspected ANSI cell
replays cover 120- and 160-column detail, 40 by 12 reading, Report and no-color
restart. These are replays with a chosen font/background, not OS screenshots.
A new six-size native matrix is not claimed.

The narrow reader reaches assertion origin after four PageDown presses and
grounded-code origin after six; eight bounded page captures keep read and return
controls visible. Report shows both pending findings while Review is filtered
to one. Five normal shared-dispatch exports produce JSON, JSONL, CSV, SARIF and
Markdown. Every format preserves the two exact file paths and one assertion plus
one observed source citation per finding, with zero explicit model claims and
no invented automated reasoning. Markdown per-finding labels agree with Review.
No-color restart retains the selected literal path and corrected label.

Two observations, zero human decisions, source bytes, context and prior tool
results remain unchanged. Exactly five completed export receipts and eight report
files are added and authenticated. No campaign, accounting row, provider request
or target-source execution is added. Workspace spend remains unavailable.

All 6,594 repository inputs and thirteen frozen programs remain unchanged during
the final native run. Only this assessment is revised afterward. The CLI SHA-256
is `c0ecb1f3dd46af38fec6d04ec486d4d706ad49c2d802c3ed9cd2466757af8c9b`.
The earlier UI-only native run retains its 21 machine passes, zero failures,
25 captures, three formal questions and eight inspected replays. It provides no
export-classification claim. Both sets of failing regressions remain evidence.

Evidence root:
`scripts/devex/artifacts/imported-evidence-origin-20261025/`.
Final native captures:
`native-attempt-2/native/J362/20261025-023953/J362/`.
The root retains test/build/lint/risk logs, repository/program manifests,
persistent-state and five-format export checks, review answers and image hashes.
Summary verification uses a separate dirty unsigned receipt, preserving the
signed published receipt. This draft is separate from the authenticated
saved-context and diagram-link checkpoint awaiting publication approval.

## Acceptance limits

The observed classification and origin-label defects are corrected locally.
This supplies no model opinion, detector-quality estimate, verified security
defect or additional model allowance. Sixteen real requests were already spent;
this correction adds none. Broader module usefulness, scope quality, context
experiments, reusable lessons and complete operator experience remain open.
Four broad delivery items retain local acceptance and five remain open.
