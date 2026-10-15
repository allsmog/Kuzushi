# Review stage identity and cost attribution

Inspecting the actual application Review's legacy stage tag exposed a separate
receipt defect. The model stage is the third row, but `triage_stages` attached
classification cost to the second row, deduplication. Two existing tests asserted
that placement. A new regression reproduced the defect before the fix: a known
synthetic $0.125 model cost was absent from the model row.

## Corrected behavior

The model stage now owns its cost report, including unavailable provider charges,
estimates and explicitly reported zero. Run totals and reservation accounting are
unchanged. Deduplication no longer receives classification cost fields.

New receipts add `stageKind=model-review` and `stageLabel=Model review` to the
model stage. Per-finding model outcomes and runtime errors add the same kind.
The stage's existing `model` field remains the selected model; a summary line
also names it for CLI and terminal readers. The private builder uses a model
review name. No runtime, provider or model selection behavior changes.

The old `stage=haiku` value remains a deprecated compatibility alias. It does
not identify an executed model. Unapplied opinions retain `stage=model-opinion`
and their explicit application status. Stage order and result authority stay
unchanged. The module and release documentation explain the cost-field migration:
new consumers should find the model stage by kind, while historical readers
should use run totals rather than the old deduplication cost. Stored receipts
are preserved, including the earlier actual Review.

## Verification scope

Evidence is retained under `/tmp/kuzushi-review-stage-cost-20261015`.
The regression retains its failing pre-fix log. Focused triage checks cover known,
unknown, estimated and explicit-zero cost, failure summaries, consensus, cache
behavior and selected model metadata. Shared prepared dispatch checks exercise
source-bound results and retained classifications when source changes.

Running the focused suite also exposed three stale test fixtures that attempted
model work without an approved allowance. Their synthetic runtimes now bind an
explicit one-call allowance, reserve and settle it, and assert one committed call
with no unresolved reservation, including after source drift. The production
admission gate remains intact. The retained logs also include a test-helper API
compile correction; no failed check is credited as passing evidence.

Sequential native J184 reuses the owned inert source fixture and two clearly
labeled synthetic runtime outcomes. Its helper checks both actual prepared
dispatch results for correct model-stage cost, unchanged run totals and retained
compatibility tags. Replay names the selected model before the journey reads
both source revisions, records a scripted human deferral, exports and restarts
without color. The helper does not initiate product work beyond the existing
explicit fixture hook, and it creates no live provider request. Synthetic
$0.01 outcome costs are accounting fixtures, not measured provider charges.

Final verification passes 145 focused Rust checks: 76 triage checks, two shared
prepared-dispatch checks, 55 Replay checks and twelve source-evidence checks.
The fixture hook is exercised separately by native preparation. The workspace
build and CRAP-risk proxy over both changed production files pass.

Final J184 is `tui-v3/20261015-093435/J184`: 18 machine passes, zero failures,
21 text/ANSI capture pairs and four pending human judgments. Replay visibly
names the selected model. Both new receipts keep synthetic classification cost
on their model stage. Two observations, two automated decisions, one scripted
human deferral and four result artifacts survive export and no-color restart.
No provider request or target source execution occurs.

The installed wrapper uses a frozen bundle, SHA256
`48661b685f4b0fe73cfbd7349069908152280a4118243ee8458c3a31a8c8a588`.
All 4,222 crate/build/toolchain inputs and 675 runtime/test inputs stay unchanged
through final verification. The native helper uses an immutable copy of the
passing core test executable. The driver is unchanged.
All ten repository quick-summary commands pass. The receipt retains four
documented limitations for CI/platform coverage and commands excluded from quick
verification. No full Rust-suite or release qualification follows.

Human judgments, actual model usefulness, complete phase/module qualification,
all interface paths and full terminal reference parity remain open. The pending
source-grounded application Review is a different unapproved job. This increment
spends no live-model allowance and does not approve that job. Exploit development,
reproducers and vulnerability patching remain excluded.
