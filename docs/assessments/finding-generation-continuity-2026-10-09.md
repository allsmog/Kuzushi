# Review generation continuity, October 9, 2026

Passive Review refresh previously anchored the page to a generation id. When
a new observation replaced that generation, the reader returned to the first
page even when the same finding remained in the query. Page metadata now adds
opaque version-one continuity anchors. They prefer the exact generation, then
follow exactly one row with the original identity and fingerprint. Ambiguous
generations and related variants are not selected implicitly. The query and
policy boundaries remain unchanged; exact anchors and snapshot-bound cursors
retain their public behavior.

The TUI uses continuity for passive page and cursor navigation. Explicit pins
retain their original generation and read watermark and are disclosed outside
the current list. This distinction exposed a source-binding defect: a newer
visible row with the same identity could supply the current watermark to an
older displayed generation. Manual decisions now prioritize the captured pin,
then the review frame, then an exact visible generation. False-positive
decisions use the same helper. The shared writer rejects changed-source actions
at their original watermark; opening the current row explicitly binds a new
decision to the replacement. Existing decisions remain in history.

Ninety-eight distinct focused checks cover query paging, strict cursors,
identity/fingerprint continuity, variants, missing or ambiguous anchors,
historical pins, draft/scroll retention, source binding, manual writes,
hydration and finding presentation. The workspace build passes. The first risk
failure was a long fixture preparer; its row construction now has a separate
helper. The complete risk gate passes for 512 changed code files. The two
ignored native fixture entry points are not included in the test count.

Evidence root: /tmp/kuzushi-finding-continuity-20261009.
J145 uses an owned 800-finding synthetic ledger, one externally replaced
generation and an explicit TUI decision on the current row. Headless prepared
dispatch consumes the returned navigation anchor before and after replacement.
No model, scanner or target-code execution occurs. Source changes are limited
to one planned inert comment edit.

Final J145: /tmp/kuzushi-finding-continuity-20261009/final-tui/20261009-134915/J145.
It records 27 machine passes, no failures, four operator questions and 25 live
captures. Every capture authenticates native SHA-256
7117e946cf0316062ea5130ccc6dca125101a29b05cbd62e592ad3d301d5f511.
ANSI and text projections agree. All six sizes and no-color restart are
captured. Sixteen projections match the previously read run after timestamp
and hex-identity normalization; nine changed/new projections were read
separately. Four scoped agent judgments pass, with operator approval false
and raw REVIEW_REQUIRED retained. Native checks preserve 801 observations,
two decisions and the single planned source edit. No model or scanner runs.
At 40x12, Enter explicitly opens detail, paging reaches the recorded verdict,
and q restores the same later ledger page. The earlier list-only paging check
was too weak and remains retained as failed screen evidence.

All ten quick repository gates pass in verify-final.json in the evidence root.
The receipt records a dirty worktree and possible drift during verification;
it does not establish a clean committed tree. Final documentation-only updates
are checked separately. Raw operator review remains distinct from scoped agent
screen judgments. The generic pin/filter recovery hint and automatic detail
behavior on resize still need product polish.

Retained failures include the fixture assuming internal ids were exposed in
public finding rows, a weak open-completion assertion, typing a draft while
Navigation mode owned input, and an incorrect expected seeded verdict. The
fixture now uses public anchors and waits for the seeded confirmation before
typing. It also uses the actual rendered pin wording and explicitly tests
narrow detail reading and return. Unit failures exposed the actual generation/source-watermark mismatch
and verify its correction.

Remaining: full live-model investigation, large-monorepo execution,
cross-policy continuity, many simultaneous replacements, cross-platform
performance and complete reference-product usability remain unproven. Exact
historical pins require an explicit current-row inspection before a
changed-source decision. All broad delivery milestones remain open. Work is
uncommitted on main.
