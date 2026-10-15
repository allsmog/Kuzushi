# Distinct Review readers and retained composer input

Review assigned `G` to both goal relevance and finding groups. Dispatch searched
the goal action first, while the compact footer advertised groups. The previous
collision tests constructed Prompt mode, where ledger-reader bindings were
absent, so those checks did not exercise the conflicting navigation state.

Review now keeps `G` for groups and uses `O` for goals. The footer and key catalog
read the same action definitions. Typed `groups` and `goals` commands stay
unchanged. Groups retain their selected-run/filter membership; goal relevance
remains an independent workspace view against a saved brief. Neither reader
changes finding validity or starts a scan.
Idle Review navigation uses a tighter two-space footer gap and concise detail/paging
labels so both readers stay visible with Answers and detail paging at 120
columns. Narrow layouts retain the existing wrapped controls and `/keys` access.
When a captured bulk review owns the return path, the same key is labeled
`G return`; its earlier long label could disappear from the footer.

The ledger-reader bindings also used to disappear when Navigate retained a
composer draft. They now follow the active input owner. Prompt mode types text;
Navigate opens readers while preserving text, cursor and finding selection.
Returning to Prompt exposes the same unsent text. Reader entry does not discard
or submit it.
Query-drafting and ledger-paging bindings retain their previous empty-composer
restriction. Enabling read-only readers does not authorize replacing a held
draft with a filter command. A focused reducer test protects that distinction.

Focused tests cover the composed Review keymap with backlog on and off, with
empty and retained drafts, across six sizes. Full reducer tests use both legacy
and Shift-modified uppercase encodings and verify distinct goal/group entry,
finding selection, composer text and cursor. The existing advertised-key test
now also checks the surviving `End` last-row action and goal reader instead of
rejecting that already supported action. It starts no discovery work.

## Verification

J276 uses labeled policy observations from the existing owned goal fixture.
It reads groups and their members, opens goal relevance, restores an unsent
multiline draft, returns through both readers, and restarts without color. It
must leave the source, three observations, finding decisions, goal assessments
and provider accounting unchanged. J274 separately exercises goal writes,
conflicts, exact history and restart using the new default shortcut. J117 also
checks `G` return to a captured bulk relationship review, atomic accept/unlink,
stale-selection refusal and independent finding decisions. These are
source-only UI tests; no provider is invoked and target source is never executed.

The original failing collision test remains in
`/tmp/kuzushi-review-controls-20261015/keymap-regression.log`. The first
advertised-key run exposed its stale missing `End` case and remains in
`advertised-regression.log`. The first native J276 run is retained under
`tui/20261015-032756/J276`. Two expectations checked the prior Prompt capture,
and a restoration expectation waited for a log line that Review does not draw.
The corrected journey captures navigation explicitly and uses the paste inspector
to verify folded multiline content after its round trip. The run also exposed
the crowded footer; a focused Answers/detail test reproduced the missing goal
control before the spacing change. J117's first setup stopped at its old direct
read-only SQLite connection. The existing checkpoint-safe reader verifies the
preserved database without changing its records. Its next run opened the source
correctly but expected an older detail heading. The final journey checks the
actual source excerpt, Review surface and visible return control.

The v4 source passes 45 selected Rust checks, including the existing 18
investigation snapshots and 120 phase/size/profile render cases. Final v5 passes
50 selected checks, including real bulk-review behavior and the 18 snapshots,
plus the locked workspace build. The only Rust/build delta after v4 is the
conditional bulk-return caption. Reconstructing the older caption reproduces
that file's recorded v4 hash; the other 4,175 inputs are identical. The full
120-case matrix was not repeated for that caption. All 4,176 v5 Rust/build
inputs match before tests and after build.

The frozen v5 native SHA-256 is
`cb83a03c89b7dccd697ffce471413047d03453e52ef962c53ec04c3523f13c66`.
Fourteen executables, including the native fixture test, are retained. Runtime
manifests record 262 inputs, including the journey files, helpers and snapshots.
Evidence lives under `/tmp/kuzushi-review-controls-20261015`.

| Journey | Frozen build | Final evidence | Machine checks | Capture pairs | Human judgments pending |
| --- | --- | --- | --- | --- | --- |
| J276 readers and draft restoration | v4 | `final-v4-J276/20261015-035319/J276` | 29 pass, 0 fail | 27 | 2 |
| J274 goal assessments and recovery | v4 | `final-v4-J274/20261015-035352/J274` | 46 pass, 0 fail | 36 | 3 |
| J117 atomic relationship review | v5 | `final-v5-J117/20261015-040008/J117` | 30 pass, 0 fail | 30 | 6 |

J276 preserves the three observations, zero finding decisions, zero goal
assessments and all source bytes through reader navigation, multiline-paste
inspection, six sizes and no-color restart. J274 retains four assessment
revisions and the exact older brief after an explicit later-brief choice.
J117 accepts and unlinks the selected three relationships in two atomic batches.
A concurrent single-edge change refuses the entire held unlink. Four raw
observations, zero finding decisions and zero rekeys remain. Every final journey
makes zero provider requests and never executes target source. The assistant
inspected the controls, source-return, compact forms, conflict, history, paste
inspection and restart captures. All eleven human judgments remain pending;
each journey ends with `REVIEW_REQUIRED`.

Human UX judgments remain independent from machine checks and
assistant capture inspection. Reference-product parity and complete product
acceptance remain unproven. The prior eight-request live allowance is exhausted;
the separate Scan approval remains unanswered.
