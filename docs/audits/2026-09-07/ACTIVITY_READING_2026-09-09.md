# Run Focus reading — 2026-09-09

Run Focus Output now moves down immediately after `g` goes to the top, and after repeated upward scrolling reaches it. Manual movement clamps to the actual wrapped document. Page Up/Down uses the rendered output interior, reserving space for overflow disclosures so narrow pages do not skip content. `G` still follows the tail; `k` leaves it. The Output footer uses the existing current Ctrl+C action instead of always claiming a live trace and abort.

The renderer's existing frame/pane rectangle calculation is extracted into a small shared geometry module used by painting and scroll measurement. Task selection, canonical run projections, bounded disclosures, model/runtime policy and phase/proof ownership are preserved. Replay reuses the same interrupt-binding helper as before.

Six new reducer/render tests cover top recovery, overscroll, every output row at 40×12, resize, terminal footer text and concurrent cancellation/cleanup labels. All 169 Activity tests, 74 neighboring Run Focus tests and eight Replay regressions pass; these groups overlap. Normal CRAP-risk passes for 337 changed files. All ten quick checks pass, with receipt completion at `2026-09-09T16:54:48.209Z`; dirty-tree drift is disclosed and supplemented by fourteen tested-source hashes. The full workspace native used for acceptance is `2d4f6aa2…`.

## Terminal evidence

All three J54 trials use a labeled, process-local missing tree-sitter helper path to repeat the known local adapter failure. Installed helpers remain present. These are failed requests through the real adapter, not successful model or empirical-verification runs.

- Before the fix, `20260909-093238`, 80×24, creates failed run `tool-1788971569442-3d1aa6be9a27`. Captures 13/14 show the same Output after `g` then `j`; only the header clock changes. The footer also falsely says live trace/Ctrl+C aborts. Four director judgments are PASS, PASS, FAIL, PASS.
- After the fix, `20260909-095045`, 80×24, creates failed run `tool-1788972663404-dbf1239609f5`. Captures 13/14 show movement from the top; capture 16 exposes the complete source-build/reinstall remedy. Captures 25/26 demonstrate leaving the tail. Output says Ctrl+C exit. Fourteen machine checks and all five director review items pass.
- `20260909-095209`, 40×12, creates failed run `tool-1788972741420-9a211a8848be`. Seventeen machine checks pass and one fails. Captures 17/18 and 109/110 prove immediate movement. Captures 51–55 expose every part of the remedy, but only one content row is visible at a time; the build command first appears at page 35 of the check. The narrow header also clips away the run id. The notice in capture 09 cuts off the explanation after “Restore the…” and clips “Esc dismiss.” Director judgments are FAIL, PASS, PASS, PARTIAL, PARTIAL. This is not a passed small-terminal failure-recovery journey.

## Preserved state and remaining work

All 42 baseline run/result files, both workflow ledgers, five target source files, three proof-event tuples, operator model configuration and dependency files remain unchanged. The three isolated failures add six run/result files. No proof was selected or discarded; no staging, commit or push occurred. Owned terminal sessions are closed.

The scoped result is partial: scrolling and the Output action label are repaired, but compact failure reading still needs work. Next reclaim useful output space, keep run identity visible, and make the full notice and its dismissal action accessible at 40×12. Do not treat one-row reachability as good interaction design. The wider interaction checklist, expired-auth/concurrent recovery, empirical proof, proof-backed Fix/re-verification/Report, and whole-product acceptance remain open.

Failed checks are retained: the original empty-output scroll fixture now contains canonical recorded output; an intermediate fixture assertion overlooked the health rows; the old footer string expectation is updated; the first quick check found only test-module ordering. [Evidence, recipes, judgments, source hashes and preservation](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/activity-reading) includes a director self-review. No independent review is claimed.
