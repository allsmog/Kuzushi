# OpenAI OAuth and model-backed flow revalidation

September 8, 2026. Kuzushi `586a6fda6d` plus uncommitted changes. The operator explicitly requested OpenAI OAuth with GPT-5.5. This supersedes the earlier pending-model-choice blocker.

## Configuration and actual execution

The saved operator model is GPT-5.5 over OpenAI OAuth, shown in the UI as `openai-oauth:gpt-5.5`, with medium reasoning. Kuzushi reuses the existing operator-owned OAuth credential. No API key or new login was necessary. The selection survived ordinary global-command restarts.

A passive observer recorded real HTTP 200 responses from the OpenAI OAuth Responses endpoint, with GPT-5.5 and both authorization/account headers present. Only booleans and allowlisted request metadata were recorded; no credential values or prompts are in the observer log. The initial successful Ask omitted reasoning; after repair both Ask and threat-model requests explicitly sent medium. No different model was tried.

The real Map journey selected Gather repo context, Map entry points, and Build threat model in Setup, then explicitly launched. Context and entry-point extraction completed. The model-backed STRIDE build completed in about 96 seconds, persisted its immutable model revision and compatibility mirror, and rendered the system summary and DFD: four nodes, three flows, one boundary, two hypotheses, zero emitted findings. The model remains unverified. Model-backed execution and persisted Map reopening are demonstrated; this is not a Scan/Prove/Fix acceptance receipt.

The target is a byte-for-byte snapshot of six real `kuzushi-descriptor` source files. It is a non-Git target, so the UI discloses an unrecorded Git revision; this run does not prove progression using a Git revision. The model's provider spend remains unresolved: observed cost is zero, not evidence that execution was free.

## Repairs from the live checks

1. **Public OAuth aliases could save an unusable model.** The generic command path accepted `openai-oauth:gpt-5.5` literally while the runtime expected its canonical OAuth identifier. That first Ask failed before any provider request. Shared model normalization now translates the public OAuth aliases while preserving the exact model id. The static chooser also offers GPT-5.5 over OAuth separately from its API-key entry; existing aliases and numeric IDs retain their meanings.
2. **The selected reasoning effort was dropped.** The OAuth body omitted reasoning, and the Rust next-step envelope had no thinking-level field. Both now carry the operator selection; unselected reasoning remains absent. Real post-repair requests show medium on the wire.
3. **Ask could not see the Map beside it.** A real successful request said no mapped context was supplied while the adjacent pane displayed the generated summary. Generic screen context fell through to an empty finding list. Map/DFD Ask now composes the existing screen receipt with a bounded model slice from the same captured revision used by the conversation key. It includes system context, selection, neighbors and linked security context. Other workflow pages retain their own screen context. The existing untrusted-data fence, byte limit, history and operator-question ordering remain in effect.

Final live acceptance passes: the rebuilt Ask describes the mapped crate and, after an additional restart-page correction, names the selected component, its exact flow, neighbor and trust boundary. The context now uses the effective Map page chosen by the renderer, including Summary on a fresh restart. The earlier HTTP 200 responses alone did not prove that useful Map context was present.

## Audit findings that remain relevant

Later revalidation: default source-body grounding and foreground Map completion are now repaired in the tested paths. The latest real OAuth Map also accepts successfully and resumes at Scan. The findings below remain the record of this earlier run. [Source grounding](SOURCE_CODE_GROUNDING_2026-09-08.md), [completion and acceptance](MAP_COMPLETION_2026-09-08.md).

Follow-up: the direct Rust test-scope case below is now corrected and verified through a fresh GPT-5.5 build. Broader reachability remains open, and the fresh run exposes insufficient source-body grounding. See [the test-scope revalidation](RUST_TEST_GROUNDING_2026-09-08.md); the bullets below preserve the findings from this earlier OAuth run.

- **P1 — Test examples become apparent production attack surfaces.** Both extracted entries are literal serde unit-test examples at `src/tool_phase.rs:210` and `:214`, inside `serde_normalizes_legacy_phase_aliases`. The catalog rates them high exposure without a test-only disposition. The generated model then discusses their parsing and unwrap behavior as hypothetical application risks. Preserve catalog provenance, distinguish test/documentation code from production before risk ranking and model grounding, and include enough enclosing source context to establish reachability. The current output is hypotheses, not confirmed vulnerabilities. [Detector](~/vibe-code/Kuzushi/crates/kuzushi-core/src/workspace/attack_surface/inspect_rust_line.rs:116), [line-based collection](~/vibe-code/Kuzushi/crates/kuzushi-core/src/workspace/attack_surface/inspect_source_file.rs:26), [real source examples](~/vibe-code/Kuzushi/crates/kuzushi-descriptor/src/tool_phase.rs:208).
- **P2 — Successful Map completion returns to a confusing Setup state.** The first resting frame says “NOTHING TO RUN,” “Threat model NOT SELECTED,” and suggests recording a skip. A footer says a result is ready; `workbench` reveals the actual completed result and its Use map action. Present the completed result directly or make its next action primary.
- **P2 — Waiting still has no token streaming.** The threat-model request exposes a running/query timer, but the answer arrives only after the complete response. OpenCode's streamed response presentation remains a useful reference.
- **P2 — Broader UX gaps remain.** The 40×12 quit disclosure, planning-option editing, provider-backed model discovery/search, richer response formatting, cancellation, and complete Scan/Review/Prove/Fix journeys are not resolved by this OAuth work.

## Evidence and scope

Evidence is local terminal text/ANSI, real persisted run artifacts and focused tests. No native screenshot or new Claude/OpenCode provider session is claimed. Historical session analysis and the OpenCode source comparison remain in the original audit. Source changes are uncommitted and preserve the preexisting dirty tree. Review is director self-review, not independent or post-commit review.

[Live evidence and final receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/openai-oauth-live/REVALIDATION.json). [Current comparison](CURRENT_COMPARISON_2026-09-08.md).

Focused checks: 59 bridge tests, 5 shared model-policy tests, 7 next-step tests, 10 catalog tests, 21 picker tests, 40 OAuth TUI tests, 31 Ask-dispatch tests and 9 screen-context tests pass. Groups overlap and are not a full-suite total. The initial failures and subsequent focused reruns are retained in the evidence directory. The ordinary CLI build passes; final repository-gate and binary provenance are in the linked receipt.
