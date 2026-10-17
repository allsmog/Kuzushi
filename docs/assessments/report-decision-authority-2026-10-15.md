# Report decision totals and authority

The actual supporting-code Review exposed an ambiguous Report headline:
`1 finding · 1 reviewed · 1 confirmed` described a model opinion with no human
decision or runtime proof. Finding details correctly preserved `confirmed · auto`,
an unverified scanner claim and `needs-runtime`. Report needed clearer wording.

The Report headline now reads `1 finding · 1 reviewed · TP: 1`. Its body explains:
"Reviewed and TP totals include human and automatic decisions. Finding details
show author and proof." One formatter supplies both study and workspace-history
totals. Ratatui and plain rendering consume the same presentation functions.
This is a wording change; it adds no new authority counts or proof claims.

Stored decisions, author, confidence, source applicability and export fields keep
their compatible meanings. `reviewedCount` and `confirmedCount` still include
automatic terminal decisions. No counts are derived from a filtered finding list
or a sampled preview. A TP opinion remains separate from deployed exposure,
runtime evidence, human authority and discovery recurrence.

## Verification

- All 186 focused Report checks pass, including source-aware selection, partial
  studies, export, history, paging, narrow rendering and plain output.
- The workspace build passes. The canonical risk gate passes 15 supporting
  checks and both changed production files.
- Native J287 has 20 machine passes, zero failures, 15 text/ANSI capture pairs
  and two pending human judgments. It uses the installed wrapper and immutable
  native binary `5b0fae9742671d622ec552cdf57a2075fc65e09812b320222a517c5b8e2749c0`.
- Six terminal sizes retain the headline; paging at 40x12 reaches the complete
  authority guidance. Study and workspace-history views retain the guidance.
  Export and no-color restart retain the compatible automatic decision.
- The existing read-only receipt helper verifies six settled investigation calls,
  three automatic decisions, zero human decisions, original discovery fields,
  both earlier decisions and unchanged source/context/configuration. Fourteen
  cumulative experiment requests remain spent. No provider request is added.

The first native attempt sent a driver Escape before the history shortcut,
closing Report. Its failed capture is retained. Removing that driver step passes
without another product change, new allowance or model request. Every controller
is terminal; the same running command was polled rather than relaunched.

The 4,228 frozen source inputs, 685 runtime inputs and 13 copied executables
remain unchanged during successful native verification. Evidence is under
`/tmp/kuzushi-report-decision-authority-20261015`, with successful captures in
`native-v2/20261015-122017/J287`. Human judgments remain open; these checks do not
establish reference-product UX parity or complete the nine broad milestones.
