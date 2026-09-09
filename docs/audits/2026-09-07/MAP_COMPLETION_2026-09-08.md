# Model-backed Map completion and acceptance

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted hardening.

The real OpenAI OAuth / GPT-5.5 Map now opens its completed result, accepts that
result, and resumes at Scan after restart. The prior findings about returning
to empty-looking Setup and accepting without advancing are corrected in this
tested working-tree journey.

## Findings and repairs

| Interaction | Reproduced behavior | Repair |
| --- | --- | --- |
| Foreground Setup Map completes | Setup showed `NOTHING TO RUN`; the completed result required a separate Workbench command. | After publishing the exact completed attempt, open its Map result. Acceptance remains explicit. |
| Use map | A selected disposition was written, but Map stayed required in the same session and after restart. | Entry extraction and recommendation now supply authenticated source identity; selection uses the same source-reuse decision as phase progression. |
| Missing or changed source | The UI could offer acceptance for an attempt that the core ledger would not count. | Keep the result inspectable, offer rerun/discard, and recheck identity immediately before Use/Continue. |

The first repair preserves the existing foreground ownership check. Background
completion, manual Run Focus, navigation away, unrelated origins and unsuccessful
runs retain their previous return policy. A result opens only when its published
receipt matches an unresolved completed Map attempt for the active target.
Draft text and input mode remain intact. In Prompt mode, `Esc` reveals Navigate
actions; `u` accepts Map, while ordinary typing remains draft input.

The acceptance failure was discovered during the first real run of this pass.
Its context and threat-model results shared a registered source snapshot, but
entry extraction and the automatic recommendation omitted the required standard
identity fields. Workflow-v2 correctly marked the combined identity unavailable
and excluded the attempt from progression. The UI nevertheless allowed selection.
The before/after ledgers and restarted terminal capture preserve that failure.

Both deterministic producers now capture the shared registered snapshot before
source-sensitive work, recheck the current tree, and add `data.snapshotHash` and
`data.treeHash` to their existing result payload. The helper reuses the existing
index bounds and reports hashing progress. Threat modeling shares the capture
and attachment helper; its grounding rules remain unchanged. No source-trust gate
was relaxed, and historical receipts were not backfilled or rewritten.

The acceptance refresh also retains the displayed attempt ID. A regression
reproduced a newer persisted attempt replacing the keypress's target; it now
selects the original displayed attempt and leaves the newer result unresolved.

Source: [completion destination](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/background_events/drain_background_events/runtime_event_drains/phase_result_destination.rs),
[shared source receipt](~/vibe-code/Kuzushi/crates/kuzushi-core/src/workspace/source_snapshot.rs),
[result policy](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/phase_results.rs:547),
[acceptance recheck](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:335).

## Real OAuth acceptance

A fresh non-Git target contains the same six real descriptor-crate files as the
earlier audit. Setup selected context, entry extraction and model-backed threat
modeling, then explicitly launched. GPT-5.5 with medium reasoning completed its
model call in about 224 seconds; the complete four-run Map attempt, including
automatic recommendation, took 228 seconds. The saved model has nine nodes,
nine flows, three boundaries and five unverified threat hypotheses. Findings
remain zero, and provider spend is unresolved.

Without further input after Start Map, the first resting frame opened Map with
`RESULT READY`. At both 120×36 and 80×24 it exposed the result and its navigation
guidance. Escape revealed `u Use map` at 80×24. All four real run results carry
the same registered snapshot/tree identity, and workflow-v2 records the combined
identity as `indexed_snapshot`.

The Map ran on executable `4bf97f114f6f…`. The final attempt-ID guard was then
rebuilt as `8dde010daebc…`; it changes acceptance selection only. The unresolved
result was reopened on that final build, explicitly accepted with `u`, and
restarted again. Both the settled acceptance frame and restart show **Map ✓,
Scan ●**, with no Scan run started. This is a two-build receipt, not a claim
that the final executable made another provider request.

The source files, saved model mirror, manifest and immutable model object remain
unchanged through acceptance and restart. The operator-owned GPT-5.5/medium
selection is unchanged. This pass made two successful OAuth requests: the first
exposed the acceptance defect; the second generated the final Map. Acceptance
and restarts made no additional provider requests. Both owned terminal sessions
were closed normally.

[First resting frame](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-completion/final-05-first-resting-120x36.txt),
[accepted Map at 80×24](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-completion/final-11-accepted-settled-80x24.txt),
[restart at Scan](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-completion/final-13-restarted-120x36.txt),
[combined run identity](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-completion/final-run-receipt.json).

## Verification and remaining scope

Final focused checks pass: 13 Map destination/acceptance tests, 52 phase-result
tests, two real registry identity tests, one source-change helper test,
27 recommendation tests, 494 threat-model tests and 35 incremental-index tests.
Groups overlap and are not a full-suite total. Earlier in this pass, 74 Run Focus
tests, one background test and two Setup-start tests passed. The normal CRAP-risk
gate passes for 191 changed code files; the ordinary CLI build passes. Fixture
corrections and the initial failures are distinguished in
[test diagnostics](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-completion/TEST_DIAGNOSTICS.md).

Final live acceptance and repository-gate receipts are recorded in the local
[revalidation receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-completion/REVALIDATION.json).
The earlier run's successful return does not establish successful acceptance;
its failed progression is explicitly retained as a before-state.

The work uses terminal text/ANSI and Ratatui buffers, with no native screenshots.
It preserves the preexisting dirty tree and existing operator-owned credential.
Review is director self-review; no independent or post-commit review, commit,
push, release certification, or complete phase-journey acceptance is claimed.
Source identity hashing was exercised on small real targets, not benchmarked on
large repositories. Live cancellation, fresh/expired login, conversation resume,
streaming, the constrained quit dialog, remaining editors and the complete
Scan/Review/Prove/Fix/Report journey still require work.
The [broad interaction checklist](INTERACTION_HARDENING.md) remains open.
