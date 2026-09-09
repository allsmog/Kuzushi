# Model-backed Review: persistence and acceptance

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening; native SHA-256 `f2438d2c979ac82a9a2515b629f895995ea85a758773cdd759ee591b60739d03`.

**Real GPT-5.5 OpenAI OAuth Review now records source identity, displays its saved decisions on the current observations, and reaches Report after explicit acceptance.** This verifies the all-rejected branch on the existing six-file source target. The full interaction goal remains open, including the Report defects below and the actionable Prove/Fix branch.

## What failed and what changed

The first real Review classified both candidates as false positives, but its result lacked source identity and its queue still showed old, unreviewed observations. The failure is preserved in [the original terminal result](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-141126/J54/04-review-terminal.txt).

| Failure | Repair and evidence |
|---|---|
| Completed Review could not be accepted because source identity was absent | `triage:run` now uses the shared source-bound execution wrapper. Registry tests cover successful source receipts and source changes producing partial results without erasing classifications or cost. [Executor](~/vibe-code/Kuzushi/crates/kuzushi-core/src/modules/triage/run_triage.rs:12), [tests](~/vibe-code/Kuzushi/crates/kuzushi-core/src/modules/triage/run_triage/tests.rs:68). |
| Finding-local decisions were ignored for observations with durable identities | The shared effective-review index and history include exact-row local records alongside applicable identity records. Human priority is retained. A SQLite regression also caught cached triage values accidentally acquiring identity-wide scope; explicit local records now keep those cached values local. [Resolver](~/vibe-code/Kuzushi/crates/kuzushi-core/src/findings/application/effective_review_state.rs:136), [scope regression](~/vibe-code/Kuzushi/crates/kuzushi-core/src/findings/persistence/open/finding_generations/tests.rs). |
| The TUI preferred an older high-severity observation over the current medium observation | Policy-aware lists now use authoritative observation order for the representative, retaining source/evidence history and the existing fold policy. The public exhaustive generation reader retains its prior sort order. [Store reader](~/vibe-code/Kuzushi/crates/kuzushi-core/src/findings/persistence/open/finding_generations.rs:30), [projection](~/vibe-code/Kuzushi/crates/kuzushi-core/src/findings/application/identity_fold_projection.rs:118). |

## Real execution and acceptance

The explicitly selected rerun used `retriage=true`, scope all, and the saved OpenAI OAuth GPT-5.5 model with medium reasoning. Identity reconciliation and model dedupe remained off. Run `tool-1788904142497-834cd5b4fe69` completed in 110 seconds: two classifications succeeded, both false positive, no failures. Provider spend remains unresolved; $0.00 is only the observed subtotal. These are automated classifications, with proof still unverified. [Safe run receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/fresh-review-receipt.json), [live terminal](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-144851/J54/07-review-rerun-terminal.txt).

The run records snapshot `716de75fc18c1c06d8c0b91f1caf866e3e1d3cac25ad519fca7269c7e883fed9` and tree `b7ca1627e08eea1888443aedbf1bb42541fc1282273848ac0038bcf9b77556e3`, matching the accepted Scan. Review attempt `d358e248-5fd5-4639-b8b4-bc39d1895722` was explicitly selected. The `n` action opened Report without launching Prove or Fix. Both current medium observations retain two sources and their automated rejections. [Acceptance](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-145222/J54/03-review-continued.txt), [accepted queue](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-145222/J54/04-accepted-review-queue.txt).

Restart at 80×24 retains Review completion, both decisions, and Report as the next action. Source files, seven Map artifact hashes and saved model configuration are unchanged. The earlier unbound Review attempt was not backfilled. This target has no Git repository; source identity is verified by content hashes, while Git revision is unavailable. [Narrow restart](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-145428/J54/02-narrow-review-ready.txt), [revalidation](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/REVALIDATION.json).

## Verification and remaining problems

Focused checks pass: 364 findings tests, 59 triage tests, 240 Review tests and 11 findings-refresh tests. These are separate test selections, not a count of unique tests. The native build succeeds with seven existing warnings. The normal CRAP-risk gate passes. All ten quick repository gates passed; the receipt is for a dirty worktree and is not a release certificate. [Logs and receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/verify-receipt.json).

Every J54 review checkpoint is judged in [REVIEW_JUDGMENTS.md](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/REVIEW_JUDGMENTS.md). One restart recipe failed its live-exit screenshot expectation because idle Ctrl+C had already exited normally; that failing run is retained. Normal exit is verified by `alternate_on=0`. No native screenshots, subagents, staging or commits were used.

The audit remains relevant to action discovery and truthful status:

- **Wrong destination label:** the accepted-result action says `n Commit & Prove`, but opens Report for this all-rejected corpus. The footer also advertises `n/N page` while the result action owns `n`. [Capture](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-145222/J54/02-review-acceptance-actions.txt). The phase-only label comes from [phase_cockpit](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/phase_cockpit/mod.rs:846).
- **Misleading Report spend:** Report says `$0.00 spent` despite the real runs' unresolved metering. Its trend currently loads campaign-only spend, which omits these ordinary module runs. [Capture](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-workflow/journeys/20260908-145428/J54/03-narrow-report.txt), [trend loader](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/campaign.rs:85). Report's return shortcut is also absent from the visible 80-column footer.
- **Planner disclosure:** optional tasks still say inline action; a selected fresh rerun still says done this pass; identity reconciliation's effective off default appears as `-`; the model is buried among options. An unedited recommended selection can still cause an unsaved-plan warning.
- **Still unverified:** Report export/retry/readback, full decision-history reading for both candidates, actionable Prove → Fix → re-verification, fresh OAuth login/refresh, and the remaining broad interaction checklist. No classifications were fabricated to enter those branches.

Next work should correct destination/key ownership and Report cost scope/completeness, then exercise export and the remaining phase journeys. This pass improves the original finding-state diagnosis; it does not establish OpenCode-level consistency across Kuzushi.
