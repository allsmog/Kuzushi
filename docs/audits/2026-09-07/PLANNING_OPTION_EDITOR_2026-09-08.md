# Planning-option editing

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

The planning-option editor now uses the shared cursor-aware field editor in both
Setup's Map plan and the phase planner. The earlier terminal reproduction—Left
followed by `9` appending to `200`, and Delete clearing the complete value—is
recorded in [the quit follow-up](QUIT_VIEWPORT_2026-09-08.md).

## Behavior and boundaries

Arrows, Home/End, word/line editing, forward Delete, shifted characters and Unicode
paste operate on the active field. Pasted line breaks are retained; Shift+Enter
inserts one. Enter or Ctrl+S validates and saves only the session option. Escape
cancels. Outside the editor, the existing Ctrl+S persist-option action remains.
Validation still uses the descriptor-backed coercion and planning preparation
boundary. Missing or invalid options keep their exact draft and an error.

The editor occupies the primary body and identifies the tool, option and input
type. Its multiline viewport follows the actual cursor. Long validation messages
wrap and page independently with PgUp/PgDn, using the same visible geometry for
rendering and navigation. Repeated paging at the end cannot accumulate an unseen
offset. Changing text clears the stale error and resets its page. Save and Cancel
remain visible at the tested 40×12, 80×24 and 120×36 sizes.

The shell draft and task selection remain intact. Ctrl+C/Ctrl+D continue through
the shared quit policy; returning from confirmation restores the field and cursor.
The old clipped draft-with-suffix-cursor rendering has been removed.

[Field state and commit](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/planning_options.rs),
[key ownership](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/planning_option_keys.rs),
[editor rendering and error paging](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker/option_editor.rs).

## Live terminal evidence

The ordinary rebuilt CLI ran against six unchanged real descriptor-crate files.
In Setup → Map plan → Gather repo context → Sample limit, Left then `9` produced
`2090`; forward Delete produced `209`; Home then Delete produced `09`. Escape
restored the default `200`. At 40×12, invalid `200x` retained its error and draft.
Ctrl+U then `7` and Ctrl+S returned to the options list with **7 · this run**, the
same two selected tasks and no launched work.

A second draft survived Ctrl+C → Stay. Forward Delete after returning removed the
character at the restored cursor. A long bracketed paste with a newline and
`TAIL東京` remained readable at 120×36, 80×24 and 40×12. Saving the deliberately
invalid numeric text produced an 18-row error. The first page showed **1–2/18**;
40 Page Down presses reached **17–18/18**, and one Page Up moved immediately.
Escape retained the earlier session value `7`. The owned terminal exited through
confirmed `y`; no tool-run directories were created, and both the six source files
and saved model configuration remained unchanged.

[Cursor insertion](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/planning-option-editor/03-left-inserts-2090.txt),
[invalid-value recovery](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/planning-option-editor/07-invalid-retained-40x12.txt),
[session-only save](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/planning-option-editor/09-session-override-80x24.txt),
[complete error reading](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/planning-option-editor/16-long-validation-end-40x12.txt).

## Verification

Four of five initial reducer regressions failed before the repair; both initial
full-renderer regressions failed because the narrow layout hid the draft or error.
The shared field implementation fixed the reducer behavior. A subsequent renderer
test diagnostic exposed a test serializer treating the continuation cell of a
wide Unicode character as a literal space; the serializer now respects display
width while continuing to require the complete Unicode text and visible cursor.

The final planning group passes **97 tests**, the picker group **185**, and the
keybinding group **32**; these groups overlap. The nine new editor tests include
both Setup and phase-planner origins. Live checks cover Setup; Shift+Enter and
phase-planner origin remain reducer/renderer evidence. Ordinary executable
provenance and repository-gate results are recorded in the
[revalidation receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/planning-option-editor/REVALIDATION.json).

Evidence uses terminal text/ANSI and Ratatui buffers. The long injected validation
message is a rendering/reducer stress test, not a captured provider failure.
No model request is needed for these field checks; the existing successful
[GPT-5.5 OpenAI OAuth runs](OPENAI_OAUTH_2026-09-08.md) and
[Map acceptance/restart](MAP_COMPLETION_2026-09-08.md) remain separate evidence.
No native screenshot, commit, push, independent review or full workflow acceptance
is claimed. The [broad interaction checklist](INTERACTION_HARDENING.md) stays open.
