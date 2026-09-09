# Quit disclosure at constrained sizes

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

The reproduced 40×12 quit defect is corrected: the real terminal now shows eight
disclosure rows, a valid range and visible Exit/Stay actions. Paging reaches all
15 rows of the unsaved-Budget disclosure, and Stay restores the exact draft.

## What changed

The old layout reserved shell chrome, modal padding and action rows independently,
leaving no disclosure body at 40×12 and reporting `1–0`. Keyboard paging used a
separate terminal-height estimate. Repeated Page Down presses at the end could
also leave the offset beyond the rendered last page, making Page Up appear inert.

Rendering and keyboard navigation now share the actual quit viewport. If the
ordinary layout offers fewer than three disclosure rows, the same confirmation
uses the full frame. Otherwise it keeps the existing contextual presentation.
Page keys move by the visible disclosure height; offsets clamp before movement,
and Home/End use real bounds. Zero-height bodies never claim an inverted range.

Exit and Stay share one line when they fit. Otherwise each choice wraps separately,
keeping its key associated with its label. The warning, unsaved-state projection,
exit/cancellation policy and back-navigation behavior are unchanged. Draft content
remains hidden in the disclosure.

[Shared geometry](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/system/overlay_lines/quit_confirmation/layout.rs),
[disclosure and actions](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/system/overlay_lines/quit_confirmation.rs),
[keyboard navigation](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:1618).

## Live terminal evidence

The ordinary rebuilt CLI ran on six unchanged real descriptor-crate files in an
isolated target. In Setup, an unsaved Budget value of `9` was entered; Ctrl+C
opened the existing confirmation flow. No tool or model-backed work was launched.

- At 40×12 the first page shows rows **1–8/15**. Page Down shows **8–15/15**,
  including the complete hidden-content notice, planning selection, choices and
  default. The final page overlaps one row because it clamps to the bottom.
- After 20 additional Page Down presses, one Page Up returns to **1–8/15**.
- Resizing to 80×24 restores the contextual overlay and exposes **1–11/12**;
  End reaches **2–12/12**, including the final default line.
- Resizing back to 40×12 and choosing Stay restores the Budget editor with `9`
  intact. Escape cancels that draft. A later Ctrl+C → `y` exits normally.

[First page](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/quit-viewport/02-quit-first-40x12.txt),
[last page](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/quit-viewport/03-quit-final-40x12.txt),
[page-up recovery](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/quit-viewport/04-quit-page-up-after-end-40x12.txt),
[restored draft](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/quit-viewport/07-stay-restores-budget-40x12.txt).

The same executable reproduced the next planning-editor defect. Starting with
Sample limit `200`, Left then `9` produced `2009`, instead of inserting at the
moved cursor. Delete then cleared the whole value. Both trials were canceled,
leaving `200` with default provenance and launching no work. At that checkpoint, the editor still
stored only a string and rendered a suffix cursor. The subsequent
[planning-option repair](PLANNING_OPTION_EDITOR_2026-09-08.md) now has bounded
live acceptance. [Reproduction](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/quit-viewport/09-planning-left-appends.txt).

## Verification and limits

The final quit group passes **18 tests**. Five new full-renderer/reducer tests
cover 40×12, 80×24, 120×36, contiguous paging, end clamping, resize, exact Setup/draft
restoration and active-work wording. Smaller buffers test absence of inverted
ranges; 20×6 and 40×8 also retain both choices. This does not establish usable
disclosure reading in a physically one-cell terminal.

The broader renderer group passed 227 tests, failed one Config fixture assumption
and ignored two tests. End scrolled past the `MODELS` heading after the earlier
catalog grew, while still showing its final action. The fixture now supplies the
actual 60×20 viewport and checks that final action. Focused rerun status, ordinary
build, final repository checks and exact hashes are in the
[revalidation receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/quit-viewport/REVALIDATION.json).

Evidence is terminal text/ANSI and Ratatui buffers. Active-work wording is tested
with simulated running state; real cancellation is still unaccepted. No native
screenshot, provider request, source commit, push, independent review or complete
workflow acceptance is claimed. The [interaction checklist](INTERACTION_HARDENING.md)
remains open. The planning-option defect reproduced here is addressed by the
subsequent follow-up linked above.
