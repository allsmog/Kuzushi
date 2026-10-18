# Named context and lesson choices

Draft on main after `dd00ef73e237488465141375d1861bc865f84d29`, including
the preceding retained-draft repair. Evidence:
`/tmp/kuzushi-lesson-copy-choices-20261018`.

Copy confirmation now names the selected base context and each selected lesson
revision before showing their full IDs and SHA-256 references. Operators can
identify what they chose and still inspect the exact immutable inputs. Selecting
zero lessons explicitly removes inherited lessons from the new inactive copy.

Names are captured together with their references at selection time. A catalog
refresh cannot replace that pair. The shared prepared executor receives only
the existing `threatModelRef` and `lessons` reference fields. Display labels
never enter tool input. Acceptance, source eligibility and retirement are still
enforced by the existing shared executor, rather than by a cached display name.
There is no public module or artifact migration.

Home/End and PgUp/PgDn scroll within the actual rendered confirmation bounds.
Paging clamps again after resize, and returning to the base picker preserves
the selected row while restoring its visible origin. At 40 columns, compact
footer labels keep `Enter copy`, `Esc base` and `Home/End read` visible.

## Verification

Seventeen TUI tests and 23 Core lesson tests pass. The TUI count includes the
fixture helper. New checks cover frozen labels/references, missing catalog rows,
reference-only dispatch input, eight-selection limits, safe labels, zero
selection, resize/paging and actual compact rendering. A real shared-dispatch
regression retires a lesson after selection and verifies that copying fails
while preserving the unsubmitted form. Workspace build, TUI Clippy and the
CRAP-risk gate pass; nine changed production files are scored.

Final sequential J118 is
`native-v2/native/J118/20261018-040135/J118` under the evidence directory:

- 34 machine passes, zero failures, eight pending human UX judgments.
- 37 live text/ANSI capture pairs; editor and copy confirmation cover 120x36,
  160x48, 96x89, 80x24, 60x20 and 40x12, followed by no-color restart.
- Fifteen selected terminal-cell replays were inspected, including all copy
  widths, full references, return navigation and the retained draft. These are
  ANSI cell replays, not OS screenshots or formal human approval.
- Fourteen frozen programs, 4,632 source inputs and 813 runtime inputs retain
  their hashes through execution.
- Native SHA-256:
  `05461ca709858473fde5913a30c418282a54f1412d1ec8feedfcf67719d3e3ea`.

The independent verifier compares both confirmation screens with the exact
base and accepted lesson references, checks the full lesson digest at 40
columns, authenticates capture provenance and checks unchanged source/active
context. Before approval, returning to the picker and reading the confirmation
creates no copy. The final ledger has one synthetic observation, one original
scripted human finding decision, and draft/accepted/retired lesson revisions.
One inactive copy retains accepted revision two. Retirement blocks future use
without removing historical reading. The unrelated unsaved note remains outside
the copied context and lesson ledger.

The first native candidate stopped at an assertion that expected the lesson
name after paging past it. The name was already visible at Home. Inspection
also found hidden copy controls at 40 columns, which were corrected before the
final run. The failed candidate is retained. An earlier test compile failure
used invalid fixture ID construction; tests now explicitly parse typed IDs.

No live provider request, campaign job, work attempt, source execution or
vulnerability claim is added. Earlier live usage remains fourteen. Broader
generated-lesson usefulness, large books, reference-product parity and the
remaining investigation requirements stay open. Four delivery items remain
locally verified and five remain open. This new draft is not committed or pushed.
