# Replay selected-result visibility

The compact Result reader now presents the selected result's saved summary
before its output. Replay labels the footer's findings as `Workspace`, so a
historical total cannot masquerade as the selected run's result. This changes
presentation only. Original artifacts, decisions, context and accounting remain
the sources of truth. The checkpoint stays a draft on `main`.

## Reproduced failure and repair

The prior compact layout moved every summary below the output. A partial run
with zero candidates therefore opened with a disclaimer and navigation counts
while hiding its actual result count. The footer showed a bare workspace-wide
finding count, which could describe unrelated historical work.

Two before-fix rendering regressions reproduce the hidden selected count at
40x12. The repaired shared reader leads with the original summary and removes
only an exactly repeated summary prefix from the compact output projection.
Blank lines, indentation, distinct output, warnings and errors remain readable.
A summary-only result is shown once. Full receipts and plain exports retain
their existing complete documents.

The first repair exposed a second regression: a nonzero candidate moved below
the first 40x12 frame. A separate rendering check reproduces it. Idle compact
Replay now removes the inactive composer row and decorative key-footer rule,
retaining status and both keyboard-control rows. Prompt mode with a draft
restores the composer; Navigate mode retains a held draft. Active work and decision gates keep their
normal chrome. The same layout policy drives measurement and painting.

No per-engine wording parser or guessed count is added. Long summaries remain
complete scrollable text. Keyboard paging, independent tab positions, input
drafts and workflow return are covered by the existing reader checks. The
workspace qualifier applies only to Replay; Report keeps its decision counts
and Workbench keeps its filtered projection.

## Verification

All 200 distinct focused reader, footer and chrome checks pass. The workspace
build and all ten repository gates pass, including source risk for 478 changed
code files. Final sequential J328/J279/J325 have 122 machine passes, zero failures,
102 authenticated capture pairs and eleven pending human UX judgments. Source,
runtime inputs and native binary digests remain stable throughout the journeys.

The journeys cover 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12. J328 checks the
zero-candidate count, explicit workspace total, complete narrow paging and
no-color restart. J325 checks both its nonzero draft count and actual candidate
in the first narrow frame, retained supplied inputs, call accounting and
no-color restart. J279 preserves three local passes, six observations, two
scripted FP decisions and report recovery. Each model-shaped fixture uses its
own fixed allowance with protected Review. The final matrix uses four
intercepted requests and zero live requests; reading and restart add no work.

Eighteen final ANSI cell replays were inspected, covering both complete size
matrices, no-color results, supplied input, narrow paging and report recovery.
These are terminal-cell renderings, not OS screenshots or human signoff. The
formal eleven questions remain `REVIEW_REQUIRED`. Technical timeout chains and
duplicate wide summaries remain visible UX follow-ups.

The earlier two-journey pair is archived before the reader-space repair. It
passed 73 machine checks; the additional nonzero-result regression then required
more reading space. A broader alias-reader test also exposed an assumption that
the whole receipt fits one frame. It now sets the real viewport and presses End
to check aliases through the actual reader navigation.

## Remaining qualification

This repairs one observed reading defect. Technical timeout wording, repeated
scope/receipt details, narrow chrome density and reference parity still need
operator review. The UAF engine's compile-database binding and source grounding
remain open. The complete investigation plan and all nine broad milestones
remain open.

No live provider request, target-code execution, project commit or push is added.
Historical live usage stays fourteen with no remaining allowance. Excluded
exploit, reproducer and vulnerability patch work is outside this increment.
Evidence is retained in `/tmp/kuzushi-replay-first-frame-20261017`.
