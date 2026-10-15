# Support settings navigation

J221 showed that matching experimental tools had a clear settings command but
required the operator to type it. The omitted-tool reader now owns selection
and Enter when its composer is empty or Navigate owns input. It keeps selection
by tool name and exposes every matching Experimental or Compatibility tool.
Supported defaults and exact dispatch authorization are unchanged.

Enter opens the existing descriptor-backed settings browser, never tool work.
Escape returns to the same filter and selection. Field Escape keeps its draft
before settings Escape returns to tools. Composer drafts and cursors survive
these transitions; Escape from support explicitly returns typing to Prompt.
Warning dismissal and captured input retain priority.

Seven focused input tests pass, along with ten existing settings-browser and
35 keybinding tests. The native J222 fixture uses only owned inert
metadata and catalog inspection. It exercises selection, settings, field draft
recovery, all six sizes, composer ownership and no-color restart, with no scanner
or model calls. Final J222 is
`/tmp/kuzushi-tools-support-20261012/complete-tui/20261012-002618/J222`.
It has 32 machine passes, zero failures and 19 authenticated captures. The native
binary is `/tmp/kuzushi-tools-support-20261012/native/kuzushi`, SHA-256
`c3a9ef3fed30793448b41b84ab1fce509595e1d9ea21e79712c63c40f90920ff`.
Three judgments remain raw REVIEW_REQUIRED; assistant capture review is separate
from operator acceptance. Source and all work counters remain unchanged.

At 40x12, settings back controls and field cancellation are readable at the
composer edge. The first native run's one failed assertion exposed the generic
Escape footer. A later 30-pass run retained the generic editing prompt; the final
run explicitly verifies keeping drafts. All predecessor receipts remain intact.

The locked workspace build and all ten summary gates pass. The final field-hint
change has a separate passing build and 432-file risk gate. The repository
receipt at `/tmp/kuzushi-tools-support-20261012/final-verification.json` is dirty,
remains unsigned and predates final field-hint/evidence updates. Final docs and
format checks are recorded separately. The architecture check now enforces the
selected tool through a presentation DTO. An obsolete context-only completion
fixture was corrected to retain supporting evidence without forging Map.

This is the recovery path for an empty supported-tool match. Mixed supported
and experimental lists retain their existing behavior. Complete registry
browser, reference parity, installed scanner qualification and broad delivery
milestones remain open.
