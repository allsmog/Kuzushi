# Report workflow revalidation — September 8, 2026

The saved GPT-5.5 OAuth engagement now has a usable Report exit: edit or cancel a destination, recover from export failure, read the receipt, and return to the accepted Review. All six available formats exported the same two reviewed findings. The broad interaction goal remains open.

## What changed

| Observed problem | Current behavior | Evidence |
|---|---|---|
| An all-rejected Review advertised “Commit & Prove” but opened Report. The footer advertised page keys while the result owned `n`. | Review/Prove continuation uses current journey truth. Card and footer share applicable result bindings, including remaps. Earlier unresolved phases retain precedence; existing source/selection gates remain in force. | [Result control tests](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/result-controls-tests.log), [destination projection](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/journey.rs:301) |
| Report showed campaign-only `$0.00 spent` beside ordinary runs with incomplete provider costs. It also omitted finding-local decisions from that trend. | Report uses the unfiltered journey counts and recent run-cost coverage. This target shows 2 findings, 2 reviewed, 0 actionable, and 0 proof-backed; cost records are 4 complete, 10 incomplete, 2 unavailable and 1 unreadable/invalid. | [80-column Report](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/journeys/20260908-154528/J54/02-report-overview.txt), [view model](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/report_summary.rs:5) |
| Destination editing ignored cursor/Delete/chords, Escape kept edits, and paste could reach the composer. | The shared field editor owns text, cursor and paste. Enter/Ctrl+S saves only the path; Escape restores the saved value. Quit discloses the draft and Stay preserves it. Each format keeps its path during the session. | [Key reducer](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/report_keys.rs:4), [saved/editing state](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/view_state/routes/report.rs:79) |
| Default exports used the source root, and long receipts could not be scrolled. | New defaults live under `.kuzushi/reports/`. Report wraps destinations/errors, pages through its complete document, resets to the receipt after export, and keeps the editor visible when opened from a scrolled page. | [Report rendering](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/report.rs:3), [operator contract](~/vibe-code/Kuzushi/docs/OPERATOR.md:146) |

A workspace spend total is still unavailable. Campaign job costs include retries; scan totals can include child runs. Report counts the coverage of up to 100 recent cost records using the canonical checked cost model. It does not add overlapping amounts or reinterpret campaign metrics. A complete workspace accounting service still needs explicit coverage relationships and legacy-record handling.

## Live acceptance and export readback

The 80×24 run rejected a directory destination, retained the failure, accepted a corrected path containing a comma and `界`, and exported two findings. Page Down exposed the receipt and cost details; Return restored Review. The first run exposed a stale generic Escape caption, which was then corrected and tested.

The final build exported SARIF, Markdown bundle, JSONL, JSON, CSV and VULN-FINDINGS at 120×36. Every format contains both real false-positive findings. Available identity IDs and fingerprints match; Markdown finding-file hashes match the manifest's `sha256:<hex>` values. JSONL includes its metadata record separately from the two findings. No export promotes these candidates to verified vulnerabilities. [Readback checks](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/export-readback.json).

The final 40-column check preserves the draft through quit/Stay and returns to Review after cancellation. The earlier small-terminal attempt failed cancel/return: adjacent Escape and Home keys produced literal escape-sequence text. The failed captures remain in the audit. Separating the events succeeded without a production change; this supports the paced interaction, not a universal claim about rapid terminal escape handling.

Four sequential J54 runs produced 43 captures and 22 judgment questions. Director review records 18 passes, 2 partial results and 2 failures, including the failed earlier small-terminal attempt. All four sessions restored the shell prompt with `alternate_on=0`; the native exit code was not recorded. There were no native screenshots or subagents. [Every judgment](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/REVIEW_JUDGMENTS.json), [capture provenance](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/terminal-provenance.json).

## Verification and limits

The source, accepted workflow and saved model configuration did not change. Hash checks cover six source files, seven protected Map files, four workflow files and 48 existing run receipt files. No new model runs were created. GPT-5.5 over OpenAI OAuth remains the selected model; the previous successful Ask/Map/Scan/Review requests remain the provider-execution evidence. This pass exercises their saved results and export flow. [Integrity check](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/post-live-integrity.json).

Focused test selections pass: 42 Report tests, 55 phase-result tests, 32 keybinding tests, plus the specific remapped/unbound footer test. These selections overlap. The final native build succeeds with seven existing warnings. All ten quick repository gates pass, including the normal CRAP-risk gate. The receipt is explicitly dirty and drifted during the run; all 32 code paths touched in this pass match their tested hashes. No full TUI-suite rerun or release certification is claimed. [Verification receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/verify-receipt.json), [diagnostics](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/report-workflow/DIAGNOSTICS.md).

Final native SHA-256: `22cb000b6d1db91c3c266c5c636192e44fc13f58e3345653dfa6745d92aa3162`. The first 80-column export check used `06e6b23cccbd2d1703c4f0a5236e9b12db554706298b3509b957a729febdf9eb`, before the final Escape-caption correction.

## Remaining work

The OpenCode comparison remains relevant: consistent field behavior, truthful actions and recovery still need checking across the rest of Kuzushi. This pass repairs the named result/Report paths; it does not establish overall TUI parity. [Current comparison](CURRENT_COMPARISON_2026-09-08.md).

Still open: aggregate workspace spend, readable timestamps and remaining shell plumbing copy, report receipt/destination persistence across restart, reveal-in-file-manager acceptance, rapid escape-sequence handling, completed batch journeys, real-provider cancellation/conversation resumption, fresh-login recovery, and actionable Prove/Fix acceptance. Result routing is verified by store-backed reducer tests in this pass, not another live triage rerun. No finding or proof was fabricated to complete a branch. All changes remain uncommitted. [Active checklist](INTERACTION_HARDENING.md).
