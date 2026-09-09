# Prove detail controls — 2026-09-08

The earlier audit remained relevant here: opening Trace over a pending Prove result displayed a draft action that did nothing, Page Down did nothing, and the footer still advertised controls for the hidden result. The current-build 40-column reproduction is retained with three failed review judgments.

The visible detail now owns its controls. Pending-result keys, card actions and background guidance yield to Trace or Investigation without resolving the attempt. Trace is a scrollable document; movement keeps the finding identity fixed. Source locations, multiline evidence, questions and the expansion command remain complete through wrapping. Short titles retain the selected finding, and the footer derives draft keys from the active keymap.

Escape uses the existing editor completion/clear behavior before closing a detail. Clearing preserves explicit undo; the empty prompt and footer offer back navigation. Switching between Trace and Investigation gives the newly requested view ownership. Trace refuses to open without a finding. Investigation retains its existing behavior: drafting the prepared verification command closes its form, and submitting the command remains a separate action.

## Validation

Seven new reducer/rendering regressions pass. The adjacent locked TUI groups also pass: 69 Prove, 40 Trace, 58 phase-result and 32 keybinding tests. These groups overlap. They cover actual keyboard dispatch, remapped keys, finding identity, scrolling, draft-only actions, clear/undo/back, missing findings and restoration of the pending result. The locked CLI build succeeds with the same seven existing warnings. Repository verification is recorded in the final `verify-receipt.json` below.

J54 ran sequentially against the existing labeled canary. No provider request or proof selection was submitted. Six runs retain 81 numbered text/ANSI captures and all review questions, including historical failures. The first repaired 40-column run exposed Escape closing the view before clearing its draft; the following 80-column run exposed a contradictory empty-prompt hint. Both were corrected and rechecked.

| Final live run | Size | Machine checks | Reviewed checkpoints |
| --- | --- | --- | --- |
| `20260908-211034/J54` | 80×24 | 11 pass, 0 fail | 8 pass |
| `20260908-211149/J54` | 40×12 | 11 pass, 0 fail | 8 pass |

Both final runs use native SHA-256 `26f585bbe53676e9fc091eb70a1666ae7620135f68db9c78eb320e0e424171a0`. The 17 recorded Rust file hashes match the focused test tree. Main remains at `586a6fda6d336dd4373b17bfa84c72c21ec68daa`; OpenCode remains clean at `d6855b6b47a8433462ac6aeeba882ccf734cb7f1`.

## Preserved state and limits

The five canary source files, all 32 prior run/result files, operator config and three proof events are unchanged. The selected model remains `openai-oauth:gpt-5.5`. The latest selected proof remains `tool-1788923292664-81f8b87ab38e`, model-backed, level 2, `not_attempted`, with no harness or crash evidence. The newer result remains pending. All owned journey sessions exited; nothing was staged, committed or pushed.

This validates reading, drafting and navigation over the existing result. It does not validate a new Trace expansion, empirical execution, Fix completion or the entire workflow. The ten broad items in [the interaction checklist](INTERACTION_HARDENING.md) remain open. Review was by the director; no independent or post-commit review is claimed.

Evidence: `~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/prove-detail-controls/`. `PRESERVATION.json`, `tested-source-hashes.json`, `native.json`, `verify-receipt.json`, the per-run judgments, `pass.patch` and `SELF_REVIEW.md` retain the receipts and review limits.
