# Entry-point evidence reading

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

The real GPT-5.5 Map's entry details are now readable at 80×24: five rows remain visible, and Page Down advances by those five rows. The earlier one-row viewport skipped nine rows per press. The same persisted model was used before and after; this pass made no provider request.

| Interaction | Before | Verified working tree |
| --- | --- | --- |
| Embedded Map at 80×24 | One detail row | Five detail rows |
| Page Down | Row 1 → row 11 | Rows 1–5 → 6–10; all 35 rows reachable |
| Repeated paging at the end | Scroll state could exceed the rendered end | Ten extra presses at the end, then one Page Up returns to rows 26–30 |
| Source receipt | Compact, width-limited values | Compact orientation plus complete wrapped receipt in the detail document |
| Long entry identity | Competes with row range in the heading | Range and paging hint remain visible; full name and ID are in the body |
| Empty Map composer | Footer says Tab completes | Footer says `Tab map view`; a typed draft restores `Tab complete` |

The increased document length includes complete identity and source receipts. It is not evidence of new model output. The browser still reports **0 extracted, 9 modeled, 9 model only**, unknown freshness and one warning. The final detail page exposes the complete warning that missing catalog provenance makes freshness unprovable. Generated candidates and hypotheses remain unverified; findings remain zero.

## Implementation

Rendering and keyboard paging share the actual browser geometry and the same detail formatter. The outer calculation also reuses the real Workbench, Map canvas and gallery geometry, including the Answers pane's width. Compact frames reserve two orientation rows, a selectable entry row, and the remaining space for detail. Paging first clamps the stored offset to the rendered last page, then moves by the visible row count.

The detail document retains full counts, hashes, context/tree comparisons, timestamps and warnings at every width. Long IDs are complete in the body; short IDs also fit in the sticky heading. Selection and detail scroll remain separate, and selecting a different entry resets its detail to the top. Printable keys still edit the active composer.

Source: [browser and paging](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/scene/entry_points/browser.rs), [shared browser layout](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/scene/entry_points/browser/layout.rs), [outer geometry](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/scene/gallery_layout.rs), [complete receipt](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/scene/entry_points/browser/receipt.rs), [keyboard routing](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/cursor_and_view_keys.rs), [footer ownership](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/keybindings.rs).

## Live acceptance

The final ordinary CLI build was checked in an owned tmux terminal using the unchanged six-file target and persisted model from the [source-code grounding pass](SOURCE_CODE_GROUNDING_2026-09-08.md). Text and ANSI captures provide the terminal evidence; no native screenshot was taken.

- At 80×24, seven consecutive captures cover rows 1–35 without gaps. Selection remains 1/9. The final page contains the complete provenance warning.
- Map zoom has six visible detail rows. Page Down moves rows 26–31 to the clamped final page, 30–35; returning restores the selected entry.
- At 40×24, the wrapped document grows to 64 rows; Page Down moves 30–34 to 35–39.
- At 120×36, selecting entry 2/9 opens `canonical_tool_phase` at rows 1–12/42. Typing `j` edits the composer without moving the selection; clearing it restores the Map Tab hint.
- All six source-file hashes and the persisted model hash are unchanged. The temporary session exited normally after its test draft was cleared.

An interim combined Escape/`z` input did not enter zoom. Those earlier captures are excluded from zoom acceptance. The final check sent the keys separately and verified the full Scene heading before paging and returning.

[Final paging intervals](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/entry-detail-reading/final-live-paging.json), [first page](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/entry-detail-reading/final-80-page-00.txt), [complete warning](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/entry-detail-reading/final-80-page-06.txt), [resize and zoom receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/entry-detail-reading/live-resize-zoom.json).

## Verification and remaining work

The final entry-point group passes **58 tests**, and final keybinding checks pass **32 tests**. Two exact Map regressions also pass: `ready_map_embeds_its_gallery_and_zoom_keeps_the_map_tab_scope` and `map_command_bar_advertises_tab_only_when_the_gallery_owns_keys`. The 68-test Scene group passed before the final footer and singular-warning copy refinements. These groups overlap and must not be added together. An exploratory `map_gallery` filter selected zero tests and supplies no coverage.

Six new reading regressions exercise full-shell renderer/reducer paging at 40×24, 80×24 and 120×36, embedded Map and Scene, complete long receipts, end clamping, resize/zoom restoration, Answers-pane width, and typing ownership. They supplement the real-model terminal checks; they do not establish acceptance of every gallery or custom keymap.

The ordinary CRAP-risk gate and repository quick gate passed before these memo updates. The final post-documentation gate result, source hashes, exact executable hash and review are recorded in the [revalidation receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/entry-detail-reading/REVALIDATION.json). The verifier marks this dirty working tree as `driftedDuringRun`; it is not release certification. Review is director self-review, with no independent or post-commit review claimed. No source commit or push occurred.

This closes the reproduced entry-detail defect in the tested frames. Successful foreground Map completion returning to confusing Setup remains open. So do the 40×12 quit disclosure, planning-option editing, response streaming/formatting, model discovery, real cancellation/auth recovery/resumption, and the full Scan/Review/Prove/Fix/Report journey. The [broad interaction checklist](INTERACTION_HARDENING.md) remains active.

Subsequent checkpoint: [foreground Map completion and acceptance](MAP_COMPLETION_2026-09-08.md) now have real OAuth, explicit acceptance and restart evidence. Earlier open-status statements above describe this pass’s checkpoint.
