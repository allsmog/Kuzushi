# Reviewed reusable lessons, October 8, 2026

Local implementation on `main` adds manual lesson drafting, exact revision
review and explicit selection into inactive immutable context copies. Finding
observations, identities and human finding decisions remain authoritative.

The ledger requires exact-generation human confirmation and source watermark.
Each immutable revision retains origin and source metadata. Edits return to
draft; stale review fails under the writer lock. Changed confirmation prevents
acceptance and reuse. Retirement and historical inspection remain available.
Shared scan-context readers validate snapshots against current accepted lesson
revisions, and exact context inspection reports blocked lesson state.

The TUI exposes `lessons` and the Review `l` action. Four separate text fields
own their cursor and multiline paste. Escape retains a draft for `d` to resume.
Confirmation precedes each write. Accepted lessons can be selected with Space;
`u` opens the exact base-context picker and a separate copy confirmation.
Background writes preserve focus. Failed writes retain the form and disclose
that persistence is not confirmed.

Lesson tool runs and run artifacts containing lesson snapshots/digests are
excluded from automatic artifact context. Active-mirror indexing removes lesson
selection. Context reuse requires explicit exact accepted references.

Verification is retained in `/tmp/kuzushi-reviewed-lessons-20261008`.
Ten focused core tests and five lesson TUI tests pass, alongside 25 artifact
knowledge regressions and one allowance-category test. The final ten-gate quick
suite is green; its CRAP-risk proxy covers 310 changed code files. The native
build passes and the driver remains unchanged.

Final J118 is `tui/20261008-025049/J118`: raw exit 4, REVIEW_REQUIRED, 21
machine passes, zero failures and six separately recorded passing scoped
judgments in `manual-review.json`. All 23 text and ANSI frames were inspected.
The native SHA-256 is
`63ab87549f9ece44e37eb2d2e3c28ab2142886a19e8a2987f02ddcad74bac7ff`.
Screen review prompted correction of literal newline markers and footer actions
that did not belong to confirmation. Earlier runs are retained. Receipts keep
one original observation and one original human finding decision, with no
rekeys, model requests, source execution, source changes or active-context change.
The copied context is usable before retirement and remains inspectable with
`lessonState.usable=false` after retirement and restart.

The current registry census contains 108 entries. Four lesson-related tools have
narrow evidence rows in `bounded-investigation-tools.json`; this is not a full
functional module audit. The native viewport evidence covers 120x36, 80x24,
60x20 and 40x12 plus no-color restart. The complete six-size matrix, large lesson
books, general shell chrome and broad platform acceptance remain pending.

Live lesson generation, report export, cross-workspace transfer,
the complete module audit and full product acceptance remain open. Synthetic
greeting fixtures establish persistence and interaction behavior; they do not
establish live-model quality or scanner precision.
