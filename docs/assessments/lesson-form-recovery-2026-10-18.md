# Recover unfinished lesson forms

Starting another lesson action previously replaced retained text without a
choice. The regression reproduces this loss after Escape: `n` clears a multiline
draft and resets its selected field and caret. New, edit, accept, reject and
retire actions now keep modified forms until the operator chooses what to do.

Enter resumes the original form. Escape returns to the list with a resume hint.
Uppercase `D` discards the retained text and opens the requested form; it does
not save a lesson or record a finding decision. Existing confirmation remains
necessary for any write. The choice owns paste and shortcuts so they cannot
edit hidden fields, open generation planning or submit a form.

Text is compared with the form's original values. Unchanged forms, including
edits restored to their original text, need no discard prompt. Only one pending
replacement is held. Retained forms remain in memory and are target-scoped;
this change does not establish restart or cross-target recovery of unsaved text.
Saved lesson revisions keep their existing durable recovery.

## Verification

All 28 lesson TUI checks pass, including one owned-fixture helper. They cover
all five replacement actions, original text/caret/field/composer recovery,
explicit discard without submission, restored original text, paste and hidden
shortcut ownership, and visible controls at all six sizes. The workspace build,
TUI Clippy and risk gate pass. Eleven production files are scored, including the
two unchanged production files in the earlier staged Report correction.

Sequential native J118 and J120 use one frozen build:

- J118: 49 machine passes, zero failures, 52 capture pairs and ten pending human
  judgments. The six-size choice can resume or return without writing, preserves
  the draft through inactive context copying, and requires explicit discard
  before opening retirement. The normal reason and confirmation still follow.
- J120: 29 machine passes, zero failures, 28 capture pairs and seven pending human
  judgments. All four saved lesson states survive supported exports and restart.
  Lossy formats disclose omissions; workspace history does not claim a completed
  scan. The earlier Report correction remains intact on this build.

Twenty ANSI cell replays were inspected. They are terminal-cell renderings,
not OS screenshots or operator UX approval. The first J118 attempt retains
the combined Escape/letter sequence that the terminal interpreted as an Alt
chord. The journey now observes the list transition before sending its next
letter. The production key parser and native journey driver remain unchanged.

Independent checks authenticate dimensions and text/ANSI hashes, all lesson
revisions, exact copied references, source and active-context bytes. J118 retains
one original observation, one original scripted human finding decision and
draft/accepted/retired revisions of one lesson. The context copy contains only
accepted revision 2. Retirement makes it unusable for new scans while preserving
historical inspection. The separate unsaved note is never persisted or copied.
No campaign or model accounting is created by the choice.

Evidence root: `/tmp/kuzushi-lesson-form-recovery-20261018`.
Final J118: `native-v2/native/J118/20261018-052426/J118`.
Final J120: `native-v2/native/J120/20261018-052756/J120`.
Native SHA-256:
`ce5428ada4d05b212bdc45618e9473d55c089a63418c4bc1651e60be80c5abc3`.
Fourteen frozen programs, 4,641 source inputs and 813 runtime inputs retain
their hashes before and after both journeys. `native-evidence.json` and
`native-v2/independent-check.json` record the respective artifact checks.

No live request or target-source execution is added. Fourteen earlier live
experiment requests remain spent. Full UX acceptance and the original broader
delivery requirements remain open. Four delivery items are locally verified
and five remain open. This draft on main follows `2b31d9267d` and includes the
earlier staged Report correction.
