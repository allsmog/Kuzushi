# Retained lesson draft during context copying

Draft on main after `dd00ef73e237488465141375d1861bc865f84d29`.
Evidence: `/tmp/kuzushi-lesson-draft-preservation-20261018`.

Saving a context copy cleared the retained lesson form. An operator could
draft a note, return to the browser, copy an already accepted lesson into
context, then lose the unsubmitted note. The focused regression reproduced
`form: None` after a successful real shared-dispatch copy.

Context-copy completion now preserves the separate form. Completing a lesson
form still clears that submitted form. The regression checks the retained
multiline text, Unicode, active field, editor cursor, composer and navigation
view, then resumes it with `d`. Existing background focus and explicit
confirmation behavior remain covered. No public module or artifact changes.

## Verification

- 23 Core lesson checks pass, including exact acceptance, immutable selection,
  retirement refusal, source eligibility and export retention.
- Nine TUI test passes include eight behavior checks and the fixture helper.
  The new regression failed before the fix and passes afterward.
- Locked workspace build, TUI Clippy and the risk gate pass. The risk proxy
  checks the single changed production file.
- Final sequential J118 records 23 machine passes, zero failures, 27 live
  text/ANSI capture pairs and seven pending human UX judgments.
- The editor is captured at 120x36, 160x48, 96x89, 80x24, 60x20 and 40x12.
  Fifteen selected terminal-cell replays were inspected, including confirmation,
  narrow browser scrolling, resumed text and no-color restart. These are ANSI
  cell replays, not OS screenshots or formal human approval.

The final native folder is
`native-v1/native/J118/20261018-034231/J118` under the evidence directory.
Executable SHA-256:
`c0208dc75802f93b1a7291b19c43dd4e5dbe4d8b5a97c8a20f1654790b66ab23`.
Fourteen frozen programs include the real TUI test fixture helper. All 4,630
source inputs and 813 runtime inputs retain their hashes through the journey.

The native workflow drafts, reviews and accepts one manually written lesson,
creates one explicitly selected inactive context copy, resumes an unrelated
unsubmitted note, retires the accepted lesson and restarts. Preview and first
confirmation states do not write early. The ledger retains exactly one original
synthetic observation, one original human finding decision and three immutable
lesson revisions: draft, accepted and retired. The copy retains accepted revision
two after retirement; it remains readable but becomes unusable for future scans.
The unsaved note never appears in the copied context or lesson ledger.

The independent verifier authenticates capture provenance, all six dimensions,
no-color restart, exact lesson content/origin, inactive copy membership and
unchanged source/active context. There are no campaign jobs, work attempts or
provider reservations from this workflow. Source is never executed. No live
provider request is added; cumulative earlier live usage remains fourteen.

## Remaining acceptance

Copy confirmation still presents choices mainly as a count and immutable IDs.
Readable base-context and selected-lesson names should improve that decision
while preserving exact revision references. Large lesson books, draft replacement
by other explicit editing actions, generated-lesson usefulness and broad TUI
acceptance are not qualified here. J304 remains the separate evidence for
delivery into downstream intercepted scanner requests.

Four delivery items remain locally verified and five remain open. This repair
does not close the full investigation or learning milestone. No commit or push
of this new draft is included.
