# Engine choice discovery, October 24, 2026

The [readiness assessment](study-engine-readiness-2026-10-24.md) identified a
remaining craft gap: stacked lists showed only eight choices in a tall terminal
without indicating that more engines existed. The engine picker now expands
its stacked list into available height and shows a scrollbar when rows remain
outside the viewport. Direction markers appear only when actual choices exist
above or below the visible window.

The generic study form layout remains unchanged. The engine-specific layout
keeps compact detail and control regions intact, preserves wide list/detail
presentation and gives tall stacked lists up to half the shared body. Cursor,
draft, context, selection, global options and spending behavior are unchanged.
Saved unknown choices remain reachable and removable. Plain output remains
exhaustive rather than reproducing viewport truncation.

The legacy `taint-iris` scan task now explicitly names `taint-iris-next` as its
replacement and discloses that it adds no engine. This describes the existing
SAST task route. The distinct standalone tool contracts and exact dispatch are
unchanged. A real task-selection test proves that selecting both task names
still produces one actual engine id. No implementation, default or maturity
tier is removed or changed.

## Verification

Thirty TUI picker/layout tests and twelve Core planning tests pass. The workspace
build, Core/TUI all-target Clippy with warnings denied and changed-code risk gate
pass. Full draft summary verification is recorded separately in the ignored
evidence root. It is not a clean signed publication receipt.

Native J356 records 30 machine passes, zero failures, 21 capture pairs and four
pending formal operator judgments. Its fixture independently counts all fourteen
rendered list rows at 96x89 and checks the actual captured scrollbar cells at the
top, middle and bottom of 40x12, including no-color restart. The same selected
engine survives resize through 160x48, 120x36, 96x89, 80x24, 60x20 and 40x12.
Compatibility guidance and Cancel retain the original global choices.

All 6,549 inputs and thirteen frozen programs remain unchanged during the
journey. The native CLI SHA-256 is
`451a2c7a91b1bf63ca0d9e7f7dca68afa1a7efd1e1f078ec8536c6de1ebb571d`.
Ten terminal-cell replays were inspected across all six sizes, the three compact
scroll positions, alias guidance and no-color restart. They are ANSI
reconstructions with recorded pane dimensions, not OS screenshots or formal
operator approval.

Source bytes and global option bytes remain unchanged. No plan, observation,
review decision, work attempt, provider-call reservation or live provider
request is created. No scanner or target source is executed. This qualifies
the reproduced discovery and continuation behavior, not detector usefulness,
model quality or complete reference-product UX parity.

## Checkpoint boundaries

The earlier 53-file readiness checkpoint remains byte-identical in the index
while its publication approval is pending. This follow-up is retained as
unstaged work with exact file hashes and backups. No additional project commit,
push or PR merge is performed. Four broad delivery items retain local acceptance
and five remain open; no milestone closes from this correction alone.

Evidence root:
`scripts/devex/artifacts/engine-choice-discovery-20261024/`, with native captures
under `native-attempt-1/native/J356/20261024-195532/J356/` and visual provenance
under `native-attempt-1/visual/`.
