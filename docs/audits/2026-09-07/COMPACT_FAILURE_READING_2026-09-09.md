# Compact failure reading — 2026-09-09

Run Focus now gives a short terminal a compact status/run-id header and primary controls. At 40×12, the tested Output pane has five content rows between its two overflow disclosures, up from one. The full run id remains visible. The effective palette binding followed by `keys` opens the complete originating control map and preserves Output position on return. Task focus says select, Output says scroll, and a blocking notice changes the compact Escape hint to dismiss. Editors, cancellation cleanup and operator questions retain their existing controls.

Long notices now present a bounded preview with an unclipped dismissal action and a route to the complete recorded message in Logs. The real source-build/reinstall remedy is visible on the first filtered Logs page at both 40 and 80 columns. This exposed and repaired another defect: Logs previously moved ten rows when only two were visible. Its page size, bounds and tail release now use the actual wrapped document and viewport; its short-screen header leaves more reading space.

## Evidence and verification

- J54 `20260909-102717`, 40×12: retained partial trial, 10 machine passes and one failure. The palette opened but its title was clipped while the alert remained; the driver now recognizes its visible input prompt and still requires the exact selected command. This run also exposed the compact Esc leave/dismiss conflict, corrected afterward.
- J54 `20260909-103135`, 40×12: all 24 machine checks complete. Captures 14/15 show the complete error and next action, 21 returns to the same F-0001 Trace, 27/28 show immediate top/down movement with five Output rows, 35 reaches the remedy in expanded Output, and 42/46 preserve Output after visiting controls. All four director judgments are recorded: PARTIAL, PASS, PASS, PARTIAL.
- J54 `20260909-103343`, 80×24: all 24 machine checks complete. Complete error, same-finding return, top/tail movement and control-map return are verified. Director judgments are PARTIAL, PASS, PASS, PASS. Wide run headers retain their existing abbreviated identifier.

Five new Activity reader tests join the six prior regressions. Focused groups pass: Activity 174, Run Focus 74, Logs 23, Replay 33, and notice banner 8; groups overlap. Two older fixtures now use real scrollable content or a viewport matching their rendered terminal. Failed results remain recorded. The full workspace build and all ten quick checks pass; the final receipt completes at `2026-09-09T17:31:07.925Z`. Dirty-tree drift is disclosed and supplemented with fourteen tested-source hashes. Live provenance matches native `df22a3ba723483ce2a8946ecf033e433b75800f31a1f2219810611d308999e2b`.

The final preservation check passes for all 48 previous run/result files, both workflow ledgers, five canary sources, all three proof events, saved configuration, dependencies and untouched prior source checkpoints. Three isolated missing-helper failures add six run/result files, for 54 total. These are failure-reading checks, not successful new model calls or empirical proof. Nothing is staged, committed or pushed.

## Remaining interaction defects

The scoped result remains PARTIAL. At 40×12 the Keymap overlay shows only one control row. Both sizes still show Esc back in Trace's footer and mode strip while the error notice owns Escape. The filtered Logs view also includes large result JSON entries after the useful error. Next repair Keymap reading space and Trace's Escape ownership labels, preserving all current reader behavior and proof state.

The broader checklist remains open: remaining inputs and focus, large/concurrent histories, fresh/expired auth, supported empirical proof, Fix/re-verification/Report, aggregate cost and whole-product acceptance. There is no independent review claim; the director self-review scores this pass 10/12.

[Evidence, recipes, judgments, patches and preservation](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/compact-run-focus).
