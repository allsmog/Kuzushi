# Review reading and navigation — September 8, 2026

The saved GPT-5.5 OpenAI OAuth Scan now has a usable Review list at 80×24: both candidates show identity, severity, unverified status, a two-line title preview, source count and location. The selected full claim starts beside its identity. PageDown reaches the detail evidence and decisions, Enter on the queue opens the same finding in Prove, and the Review page key returns to that selection. No model request was made in this pass.

This is a bounded improvement in the uncommitted working tree, not completion of the interaction-hardening goal. The original workflow audit remains relevant; its finding-title and action-discovery diagnosis has additional concrete repairs.

## Before and after

| Interaction | Previous behavior | Current behavior |
|---|---|---|
| Read the queue at 80×24 | Facets and a truncated legend consumed nine rows. The unselected candidate had no visible title; its metadata wrapped beyond the row budget. | Compact cards put identity, proof status and title first. Both saved candidates fit. Complete claims remain in the detail pane; stored titles are unchanged. |
| Know what Enter does | The footer said review; the detail pane said Enter prove even though Enter belongs to queue focus. | The queue footer says open Prove. The detail pane and its footer do not advertise Enter; the page bar explicitly scopes Enter to the queue. Movement keys remain visible. |
| Read longer details | PageDown was unbound because Workbench supplies its own key set. | PgUp/PgDn are bound on scrollable Workbench surfaces and page by the same pane interior used for rendering. Queue cursor behavior is unchanged. |
| Interpret repeated observations | A count greater than one produced the label corroborated, even beside unverified proof. | That evidence-state label says multiple observations. Confidence, proof, lifecycle, findings and decisions are unchanged. |
| Read the current sort | A narrow Learn queue was labeled proof > severity regardless of its actual ordering. | Learn retains its own ordering label. The underlying ordering is unchanged. |

The compact list retains active filter summaries; full facet counts remain in plain/wide queue output. At extremely small heights, identity and the title preview take priority and filter disclosure can be abbreviated. The six reference sizes include 40×12, but full constrained-terminal acceptance remains open. At 60×20 the current card budget still leaves spare space that could fit another short preview.

## Real session evidence

The target contains six real Rust descriptor-crate files and the previously accepted Map and Scan. The two Review groups, F-0001 and F-0002, are unverified candidates with two sources each. They are not established vulnerabilities. No decisions or verification were performed to manufacture phase progress.

Final J54: [80×24 navigation capture](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/journeys/20260908-140025/J54/02-review-navigation.txt), [paged evidence](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/journeys/20260908-140025/J54/05-detail-scrolled.txt), [same Prove subject](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/journeys/20260908-140025/J54/06-opened-candidate.txt), [returned selection](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/journeys/20260908-140025/J54/07-returned.txt).

The final harness result is 1 machine pass, 0 machine failures and 6 review-required items (exit 4). All six have explicit judgments in the [review record](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/REVIEW_JUDGMENTS.md). Live captures have alternate_on=1; normal exit has alternate_on=0. The earlier incorrect q-as-Back recipe and the first rebuilt run's inactive PageDown are retained as failed or unexercised checkpoints.

The [integrity record](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/REVALIDATION.json) confirms unchanged six source files, seven Map files, saved model configuration and all 15 existing run directories. The native binary used for final acceptance is SHA-256 d45dd051bf41215e87594fef8b6d005ce0f46a696021304bcc04c31edf9a698e. Git HEAD remains 586a6fda6d336dd4373b17bfa84c72c21ec68daa plus preserved uncommitted work. The source target is content-bound and is not itself a Git checkout.

## Implementation and verification

- [Compact cards](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/workbench/panes/review_queue/compact.rs:5) consume the existing queue model and preserve its order and selected identity.
- [Detail identity](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/hunt.rs:374) precedes the full claim. [Evidence wording](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/review_state.rs:95) distinguishes repeated observations from proof.
- [Paging keys](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/view_keybinding_groups.rs:339) use [renderer-owned geometry](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/render_app.rs:98). Existing guided-question and pending-result behavior is preserved by the extracted binding helper.
- Final focused checks: 240 Review-filtered tests, 37 keybinding tests, and 6 compact-reading tests pass. These groups overlap. The 30-frame reference snapshot generator passes; exactly the six Review snapshots changed and were inspected before copying. The remaining 24 are identical.
- Normal CRAP-risk passes. The final repository quick gate passes all 10 steps at 2026-09-08T21:04:52.495Z; [receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/review-reading/verify-receipt.json). It records a dirty tree and drift during the run, so it is not release certification. Quick mode excludes the full Rust suite, coverage and cross-platform acceptance. The first quick run stopped on formatting in the new test assertion; only that test file was formatted. No gate bypass is used.

Director self-review only; no independent reviewer or post-commit review is claimed. Changes remain uncommitted.

## Remaining work

Complete actual Review dispositions with defensible evidence, then Prove, Fix and Report. Audit queue paging and very narrow reading, full batch-result flow, expired-auth recovery and restart of conversations. General back semantics, paragraph-length model titles, planner wording/model visibility, and noisy operational footer copy remain open. OpenCode remains at d6855b6b47a8433462ac6aeeba882ccf734cb7f1; no OpenCode code was changed. Kuzushi is closer on finding visibility and focused keyboard reading, but this does not establish overall UX parity.
