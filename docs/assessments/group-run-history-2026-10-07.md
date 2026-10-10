# Selected run history in grouped Review

Grouped Review now distinguishes the runs that observed a finding from the run
of its displayed current observation. This prevents an earlier selected scan
from appearing to select an older source snapshot. A missing observation never
establishes a fix at a different SHA.

The existing projection passed a focused three-run regression before any
production change: selecting the middle run retains its finding and excludes
unrelated history. The change adds explicit receipts and TUI copy rather than
altering finding identities, decisions or grouping policy.

`findings:groups` returns additive `selectedRunIds` and per-member
`matchingRunIds`. Selected parent references expand through the existing Scan
receipt reader. Membership is sorted and unique. The current generation and
its `runId` remain explicit. Older serialized pages can omit the added fields.

Nine core grouping tests, twelve relationship TUI tests and the shared prepared
group-tool test pass. The native build passes. All ten repository gates pass in
`/tmp/kuzushi-review-groups-20261008/history-verify-final-summary.json`, including
workspace/all-target checking, format, model policy and CRAP risk.

Final J116 evidence:
`/tmp/kuzushi-review-groups-20261008/history-tui/20261007-230238/J116`.
Raw REVIEW_REQUIRED and exit 4 remain unchanged: sixteen machine passes, no
failures and five human-review questions. Separate `manual-review.json` records
the scoped passing judgments, and `ansi-review.json` records sixteen inspected
frames. Wide, 40x12 and no-color restart captures expose both run identities,
preserve selected-member navigation and show source-comparison guidance.

`history-check.json` records three retained observations, no finding verdict,
no rekey, no provider request, no source execution and unchanged source bytes.
The binary SHA-256 is
`b88dc10491b492f340e31c30c8827a7c46de36c6a2ca7f4948c0502bd808f772`.
The first J116 run and its separate NEEDS_MORE_EVIDENCE judgment remain: its
two narrow paging moves had not reached the run-history rows. The final journey
captures the full narrow read path and corrects the singular run label. The
driver is unchanged.

This is owned fixture validation. It does not establish live model quality,
source fix adjudication, every run/filter combination or full investigation
readiness. The 40x12 reader exposes two body rows and requires several paging
moves. Global route/posture labels and historical startup notice copy remain
separate quality gaps. Bulk review, reviewed reusable lessons, monorepo editing,
the full tool audit and complete reference-quality acceptance remain open.
