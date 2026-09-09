# Interaction hardening

Goal: make Kuzushi's analysis and reporting workflow reliable end-to-end, with usable TUI interactions and the selected GPT-5.5 OpenAI OAuth runtime.

## Current operator scope — September 9

The operator explicitly removed automatic vulnerability reproduction from this goal. Do not resume empirical proof, exploit/trigger harness generation or execution, the Linux reproduction workstream, or crash-based patch re-verification. These paths are excluded from acceptance, not marked successful. Earlier checkpoint notes requesting that work are superseded by this scope change.

The remaining workflow is Target → Setup → Map → Scan → Review → Report, with source-based model assessment and patch drafting/review where supported. Preserve real evidence and existing authorization/proof requirements; report unverified findings honestly. Do not weaken a proof requirement to make an excluded path appear complete.

Next: exercise one complete analysis-to-report journey using the selected OAuth model, verify the saved report and restart behavior, then finish patch-draft review, cancellation/auth recovery, and the remaining input/navigation/cost issues. No new proof runner or harness work is needed for this goal.

This is an active completion checklist, not a claim that passing the current tests proves the goal. The preceding turn made progress by revalidating the audit, building current source, and reproducing input failures. Work starts from `586a6fda6d`; preexisting backend edits belong to the operator and are preserved.

## Acceptance work

Latest checkpoint: [Control-map reading](CONTROL_MAP_READING_2026-09-09.md) restores useful narrow control-map space, complete key labels, measured paging and notice-owned Trace Escape labels. Focused tests, all ten quick checks and the final 40/80-column terminal checks pass for those paths. Wrapped section-heading grouping remains partial. Its proposed execution work is superseded by the operator scope above; the remaining checklist is still open.

Previous detail-controls checkpoint: [Prove detail controls](PROVE_DETAIL_CONTROLS_2026-09-08.md) gives Trace and Investigation ownership of their visible controls over a pending result, preserves complete Trace evidence through scrolling, respects remapped draft keys, and clears focused drafts before back navigation. Final 40/80-column reading, drafting, clear/back and view-switching checks pass without a new provider request or proof selection. The broader checklist below remains open.

Previous checkpoint: [Prove result reading and inconclusive assessments](PROVE_RESULT_READING_2026-09-08.md) repairs incomplete model verdicts being labeled negative, gives pending results a readable body, and fixes form priority and indented scroll extent. Real GPT-5.5 OAuth selection/restart and final 40/80-column reading pass.

Earlier checkpoints: [Unresolved Review and Setup disclosure](UNRESOLVED_REVIEW_2026-09-08.md) repairs missing-reachability evidence being classified as a false positive. Real GPT-5.5 OAuth retriage preserves four unresolved candidates and their previous decisions; acceptance/restart does not advance them past Review. Setup shows model and credential type at 40/80/120 columns. [Ask recovery](ASK_RECOVERY_2026-09-08.md) and [Report workflow](REPORT_WORKFLOW_2026-09-08.md) remain verified in their bounded paths. [Prove preflight](PROVE_PREFLIGHT_2026-09-08.md) now routes empirical verification through shared authorization and displays mode-specific prerequisites; 40/80-column reading and the real headless not-attempted path now pass. Supported execution through Fix and the broad items below remain open.

- [ ] Text fields accept normal keyboard editing, shifted characters, Unicode, paste, multiline prose, and visible cursor movement. Inputs reach the field that owns focus.
- [ ] Map documents are individual paths with file selection and useful validation; commas and spaces do not change identity. Context entries preserve complete prose. Editing/canceling restores the correct plan and screen.
- [ ] Numeric options allow direct entry with honest bounds; large scope sets use search and deliberate selection. Changing options does not start work.
- [ ] Questions and complete answers remain usable beside Map evidence; context, drafts, selections, history, scrolling, and narrow-screen transitions survive follow-up and back navigation.
- [ ] Findings and batch results retain identity, title, severity, occurrence, and access to full evidence at ordinary widths. Recurrence never substitutes for confidence or proof.
- [ ] Commands, forms, selectors, prompts, overlays, and background completion have consistent focus, back, cancel, and launch behavior. No swallowed keys or surprise dispatch.
- [ ] The ordinary development and installed launch paths identify and execute the intended build; packaging and runtime dependencies remain complete.
- [ ] Operator-facing copy prioritizes the decision, current state, cost/model/scope, and next action; detailed technical receipts remain accessible.
- [ ] Sequential acceptance covers fresh/resumed target, Setup, Map, Scan, Review, source-based assessment, supported patch drafting/review, Report, inline questions, expired-auth recovery, cancellation, restart, and constrained terminals with real evidence. Empirical reproduction and crash-based re-verification are explicitly excluded by the operator; other unsupported or unexercised paths stay open.
- [ ] Focused regression tests, the shipped CRAP-risk gate, relevant repository verification, and live terminal checks pass for the actual changes. Completion requires the whole checklist and an adversarial end-state review.

## First workstream: Map input fidelity

Proposal: reuse `EditorState` through a small field editor, replace delimiter-based list editing with individual document/context entries, route paste to the focused field, show a cursor and a bounded multiline viewport, and reuse the workspace file picker with an explicit Map-document destination. Preserve the descriptor preparation boundary and existing scope/model/budget policy.

Review decision: KEEP. The live current-build reproduction proves path splitting, ignored Left, and dropped shifted text. A delimiter tweak alone would still lose multiline prose and path identity. The generic file picker currently attaches knowledge-base sources, so its destination must be explicit before reuse. Empty/invalid edits must preserve the draft and prior saved value. Escape must cancel the active edit rather than submit to the shell. Focused tests must exercise the reducer and renderer, not only the text helper.

Review method: director self-review with source inspection. No independent subagent review is claimed; the repository requires an explicit operator decision for subagent launches.

Status: implemented, under verification. The focused reducer/rendering/input/exit suite passed 54 tests. Current-binary terminal verification passed at 120×36 and 80×24 for the tested field paths (comma path, cursor editing, multiline Unicode, selection, validation, cancel). Evidence: `~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-input-live/steps.md`. The full TUI run finished: 3,113 passed, 8 failed, 4 ignored. The new renderer panic-site failure was corrected and its focused gate passes. All eight original failure sites now pass focused checks after the corrections below; the full TUI rerun and repository quick gate have passed. This is not yet a completed broad acceptance item.


## Second workstream: direct configuration

Proposal: Trials and Workers open a cursor-aware numeric field with the existing 2–50 and 1–8 bounds. Enter saves, Escape cancels, and typing or pasting never launches work. Invalid values retain the draft; successful changes disarm prior large-batch review and recompute the existing worker policy. Keep the shared batch preparation boundary and explicit launch/review. Map scope becomes a filtered list of the existing whole-target, persisted eligible-leaf, and all-leaf choices; selection preserves the existing scope cap and target/revision-bound review.

Review decision: KEEP. Cycling 47 times to enter 50 trials is an observed interaction cost, and the existing controls already have pure value bounds. Direct entry must not silently clamp invalid input, dispatch from a focused field, or reuse stale review. Search must not manufacture scopes or mutate the plan while filtering. File and field editing introduced in the first workstream provide the input behavior without a second editor implementation.

Review method: director self-review against current config, reducer, renderer, and scope policy. No separate reviewer or completed journey is claimed.

Status: implemented, under verification. Numeric entry, reducer focus/cancel/paste protections, scope search, exact identity, no-match and removed-scope refusal, canceled large-scope review, changed-evidence re-review, and caps pass focused tests. Scope search and canceled 50-scope review passed live at 80×24. The live batch entry path revealed that the form opened in command mode despite advertising Enter-edit; it now opens with its controls active, and Escape closes the form. That focus correction passed live: Enter opened the field directly, 50 saved without launching, 51 retained its invalid draft, and Escape returned to campaigns. No campaign artifacts were created. Worker policy and cost evidence now wrap; focused full-frame/plain parity checks pass. The final row-alignment refinement passes rendering tests and the September 8 live 80×24 recheck (captures 09/10). The combined numeric/scope/batch-rendering check passed 20 tests.


### Additional live finding

CORRECTED for the tested paths: Quit at 80×24 now wraps and scrolls all disclosures with exit/stay controls pinned. The original reproduction is `hardening/map-input-live/08-quit-80-clips-content.txt`; updated live evidence is `hardening/readability-live/steps.md`. Thirteen quit tests pass, including both modal entry paths and draft restoration.


### Full-suite diagnostic queue

The first full run took 645.66 seconds. Log: `~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/map-input-full-tui-tests.log`.

- Corrected: two new renderer unwrap sites. The pane-facing panic gate now passes.
- PASS: `reference_seed_invalidates_missing_dfd_and_replay_cache_entries`. Fixture hydration now includes the authoritative model store alongside its legacy mirror.
- PASS: `foreground_visualization_opens_contextually_after_run_focus_restores`. Production DFD refresh now invalidates and reloads both the authoritative model store and its compatibility mirror.
- PASS: `threat_regen_and_inline_ask_return_effects_without_spawning_workers`. Fixture explicitly supplies the credential-readiness state required by the unchanged reducer.
- PASS: `threats_versions_lists_ledger_rows_and_use_restores_the_selected_model`. Legacy fixture now carries a valid linked DFD/threat document; assertions retain restored content, verification, live digest, and history while allowing the required normalization migration.
- PASS: `command_catalog_covers_every_public_route_kind`. Expected set includes the two existing registered commands.
- PASS: failed/blocked/canceled snapshots include the existing Discard action. Scratch diffs were inspected; only that third action, its count, and the required extra row changed. Partial/degraded/blocked-selection snapshots stayed identical.
- PASS: the complete help-catalog assertion uses a 320-row viewport after catalog growth. Production help is unchanged.

These have not been labeled preexisting without a baseline check. Do not weaken behavioral checks merely to turn the suite green.


## Third workstream: readable batch results

Proposal: render severity and the full finding title first, then occurrence and location, then exact finding identity and run references on wrapped lines. Wrap batch counts and gate status too. Keep occurrence denominators and operational failures explicit, retain the existing ranking and Review scope, and do not turn repeated occurrence into proof or confidence.

Review decision: KEEP. The current renderer places a long occurrence phrase and location before the title, then truncates the whole row; the title disappears at ordinary widths. A wider fixed table cannot solve a constrained terminal. Wrapped lines preserve content and use the existing scrollable campaign document without adding a second findings store or changing grouping policy. Regression checks should place long paths, titles, and run IDs in an 80-column buffer and require complete text, not just a prefix.

Status: implemented. New 60/80/120-column content checks and an 80-column terminal-buffer check pass for long titles, paths, exact fingerprint, and run references. Existing batch plain/full-frame parity passes. The expected comma-spacing assertion was updated to match the more readable run list and its rerun passed. A full live batch-result journey remains open.


## Fourth workstream: constrained quit confirmation

Proposal: keep the decision controls pinned in the quit overlay, wrap its full warning and unsaved-state disclosure, and allow its body to scroll with arrows/PageUp/PageDown/Home/End. Give this modal its own scroll position so checking exit does not move the underlying page. Preserve y/Y confirmation, n/N/Escape restoration, active-work cancellation, and the complete plain output.

Review decision: KEEP. The 80×24 live capture clips the warning and the CHOOSE section. Reducing only padding would still fail with multiple drafts. A bounded body plus pinned actions preserves the decision while making every disclosure reachable. No exit policy is changed.

Status: implemented. Thirteen quit tests pass, including 40/60/80/120-column constrained bodies and full 80×24 rendering through both entry paths. Current-binary live checks show the wrapped warning, End reaching final disclosures, pinned actions, and n restoring the exact unsaved context; the temporary session exited cleanly. No exit or cancellation policy changed.


### Diagnostic corrections verified

Director review KEEP: the Ask reducer test expected dispatch without credentials even though the unchanged reducer now checks provider readiness. The test now explicitly sets the existing session-credential state and continues to assert effects without executing them. The public-route expected set is updated for two already-registered commands. The complete-catalog help assertion gets a larger test viewport after catalog growth; production help behavior is unchanged. The failed/blocked/canceled snapshots were regenerated to scratch, inspected, and updated only for the existing Discard action. These changes preserve the behavioral assertions and do not remove production gates.


## Fifth workstream: current DFD refresh

Proposal and director review KEEP: the explicit latest-DFD refresh reloads only the legacy JSON even though `read_threat_model_artifact` requires `ThreatModelStore` first. Refresh both through the existing hydration boundary, invalidating the cached authority as well as the mirror. Do not fall back to the mirror when an authoritative revision is corrupt. The DevEx seed must request the same authority state.

Status: implemented. Both previously failing DFD checks pass. A new regression starts from cached absence, commits and refreshes STRIDE, switches to PASTA, then corrupts the active object; it requires each current document and an integrity error after corruption. The five-test diagnostic run passed, and the normal CRAP-risk gate passed for 64 changed code files. The full TUI rerun (3,139 passed, zero failed, four ignored) and repository quick gate passed.


## Next workstream: Ask beside Map evidence

Source review confirms that `AgentChatView` already holds the current question, answer/error, twelve prior turns, and a target/revision/model context key. `AgentChatState` also retains the dispatch artifact target. Model calls already bind context, refuse incompatible history, record transcript events, and preserve the current view. No new agent runtime or second message store is needed to render the current thread. The comment claiming `chat` opens a conversation is stale: the current command catalog has Ask and Logs, not that command.

Proposed implementation boundary: a presentation model over the existing chat state; pane visibility/focus/scroll in route state; a renderer integrated with the Map/Scene body; input ownership before page navigation but after modal owners. Wide layouts should keep both Map and the answer visible. Constrained layouts need a compact context receipt and a reversible Map/answer focus switch so neither the full answer nor the diagram cursor is lost. Preserve the composer and explicit Ask submission; showing or scrolling an answer must never dispatch.

Director review: FIX before implementation. Simply turning on the two-line transcript would truncate answers. Splitting the entire frame above Workbench would make its phase geometry and hit-testing disagree, and at 80×24 the repeated header could consume the remaining Map body. Integrate geometry and input together, make focus explicit, keep reply completion from stealing it, and distinguish historical context from the current attached context. Model/target/revision changes must retain honest history access without resending incompatible turns.

Required checks: full long answer and earlier turns reachable; question/context identity visible; draft untouched during scrolling and Map/answer switching; background completion does not switch views or focus; modal keys stay with their modal; invalid model/auth refusal is readable; cancellation preserves the right run; new revision/target does not attach stale context; 80×24 and 120×36 layouts agree with hit-testing and navigation; plain output remains exhaustive.

Status: implemented, acceptance in progress. Answers uses the shared body geometry, an independently edited reply draft, scrollable complete text, and bounded read-only prior contexts. Ctrl+T moves focus while retaining the wide pane; Esc hides it. Drafts stay with their target during a session and clear only after matching dispatch admission. Operator questions suspend the pane and own both keyboard and paste. A live configured OpenAI coding-agent model-call attempt failed with a generic runtime error and unresolved provider spend. The pane retained its question; the discovered empty-retry-field defect is corrected with event tests. No successful response or resumed-session acceptance is claimed. The new full-suite and quick-gate logs are `hardening/answers-full-tui-tests.log` and `hardening/answers-verify-quick.log`; the earlier checkpoint below predates Ask.


## September 8 verification checkpoint

Full TUI suite: **3,139 passed, zero failed, four ignored** in 674.29 seconds. Repository quick gate: all commands passed. The runner marks every dirty working-tree run as `driftedDuringRun`; this is not a clean-release receipt. Normal CRAP-risk gate: PASS for 64 changed code files. The final unused file-picker helper cleanup passed its focused check (1/1); no broad-suite repeat is implied for that small cleanup. Logs and source-content hashes are under `hardening/`; the latest structured receipt is `hardening/2026-09-08-revalidation.json`. Final memo edits record these outcomes after verification.

The implementation remains uncommitted. This checkpoint does not complete the broad interaction goal: inline Ask, ordinary launcher selection, remaining field/copy consistency, and full real runtime journeys are still open.

Final CLI rebuild passed and reports alpha.14 / `586a6fda6+dirty`; its SHA-256 is in the structured receipt. Seven preexisting dead-code warnings remain. The final memo content check is run separately after recording verification outcomes.


## Ask acceptance checkpoint

The complete TUI run passed 3,155 tests, with zero failures and four ignored. Later failure-draft restoration and context-label changes pass the 19-test Ask group; the 30-test Ask/runtime regression group also passes. Final production changes pass the repository quick gate and CLI rebuild. The additional label test and final memo updates followed the quick receipt. Details and source/executable hashes: `hardening/answers-revalidation.json`.

Live tmux text/ANSI checks covered 160×48, 80×24, and 120×36 with separate shell/Ask drafts. The configured OpenAI coding-agent request failed with a generic runtime error; observed cost is zero with unresolved provider spend. The empty retry field discovered there is corrected through event tests. The running session used the earlier Ask binary, explicitly recorded in `hardening/answers-live/captured-binary.json`; final production source was subsequently rebuilt. The generic error remains an open recovery finding. No successful response, complete auth/cancel/restart journey, or full phase journey is claimed. All broad checklist items remain open until end-state acceptance.


## Launcher consistency workstream

Proposal: source-checkout wrappers and `pnpm dev` build the full native runtime using the existing Cargo package contract, then launch only executable paths Cargo reports. Respect Cargo output-directory configuration; reject build failures or incomplete runtime output instead of choosing older bundled binaries. The published package still resolves its optional native package without requiring Rust. Explicit native overrides continue to select a specific executable. CI that intentionally tests downloaded artifacts must set that override explicitly.

`link:local` will back up the complete previous global package and link the checkout, so wrapper, JavaScript bridge, CLI, dependencies and MCP siblings come from one source. Repeated linking must preserve the original backup; restore must only replace the link owned by this checkout. Build and validate before changing the global installation. Retain the `kuzushi`/`kz` identity and child exit/signal behavior, and keep the caller's working directory.

Director review: FIX then KEEP. Merely preferring a newer file by timestamp can still run stale source. Linking only one CLI into an old package leaves bridge and MCP versions mismatched. An unconditional source build would also break the existing downloaded-artifact CI lane unless that lane explicitly selects its staged native binary. Use Cargo's emitted executable paths rather than guessing `target/debug`; test build failure, custom target directories, argument/cwd/alias preservation, missing sidecars, packaged execution without Cargo, and reversible whole-install linking. No independent reviewer or global mutation is claimed yet.


Launcher result: corrected in the tested source/packaged paths and on this macOS installation. Sixteen focused launcher/install tests, the release native build, packed runtime verification (empty PATH), repository quick gate, and final CRAP-risk gate pass. The global package now links this checkout; `/opt/homebrew/bin/kuzushi` and `kz` both report alpha.14 / `586a6fda6+dirty`. The original package remains at `/opt/homebrew/lib/node_modules/.kuzushi.before-local`; checked original files retain their hashes. `pnpm link:local:restore` restores it and refuses to overwrite a later installation. Restore was exercised in temporary installations, not by repeatedly replacing the user's global package.

Ordinary global TUI startup reached Setup, Map and Answers at 120×36 with an explicit temporary target and no model/scan submission. Source build checks take about three seconds on the cached checkout; package-native startup does not perform that check. Source and package dependency/version ownership now match. No published-release or cross-platform live acceptance claim is made.

The packed check found a separate manifest drift: three already-tracked public finding-identity audit/approval schemas were shipped but missing from `requiredPackageFiles`. The live CLI produces audit evidence and accepts approval requests in `crates/kuzushi-cli/src/application/findings.rs`; the corresponding Rust types live in `findings/application/identity_policy_approval.rs`. Requiring those three exact schema files fixes the inventory while preserving the unknown-schema rejection. Receipt: `hardening/launcher-revalidation.json`.

## Runtime recovery and command ownership

The previous comparison-only turn did not change interactions. This pass starts from the recorded real failure: lifecycle metadata already carried `provider_rejected` and HTTP 400, but the TUI received only an outer error string. KEEP after director review: preserve the existing bounded metadata across worker/reducer boundaries, keep raw responses private, add accurate recovery guidance, and exercise the recovery path on the ordinary executable. Rejected: relabel HTTP 400 as authentication, expose raw provider text, or automatically retry/change models to manufacture success.

Ask, planner and threat-model failures now preserve the cause and valid HTTP status. Persistence context retains the typed error chain. Ask retains the failed question without replacing newer drafts or changing focus; failure guidance points to the relevant Auth/Model/Config/Doctor surfaces and the captured trace. Cancellation remains a canceled outcome and does not offer unrelated provider-repair advice. No model/provider fallback or automatic retry was added.

Acceptance found and corrected two further interaction defects. Argument-taking palette commands now focus the visible shell input while retaining the Ask draft. Trace advertised Ctrl+T without handling it: Trace and Replay now host Answers, while unsupported configuration/modal screens reserve no pane and advertise no inactive shortcut. Final 80×24/120×36 terminal captures cover local failure → palette → Trace → retained reply → Config → explicit quit.

Focused checks pass: 28 answer/focus, 9 runtime-failure, 13 palette, 5 agent persistence/cost, and 12 core tracing tests (overlapping groups). The final quick gate, including normal CRAP-risk, passes. The ordinary global launcher rebuilt; all three isolated terminal sessions are confirmed closed. The final full TUI rerun passes 3,176 tests, with zero failures and four ignored. Evidence: [recovery receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/runtime-recovery/REVALIDATION.json) and [terminal steps](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/runtime-recovery/STEPS.md).

This pass used three explicitly selected local protocol simulations, with no external provider request. It repairs visibility and navigation around failures, not the original provider's rejection. Successful provider/auth/cancel/resume acceptance, response streaming/formatting, full batch results, all remaining field/phase journeys, and end-state review remain open. Changes are uncommitted; review was by the director only, with no independent or post-commit review claim.

The initial full-suite diagnostic run finished with 3,174 passing, two failing, and four ignored tests. One assertion expected the retired one-line error. The other caught a real duplicate-transcript regression introduced by the new notices. Failure notices now record the cause once, and the activity retains its terminal state/detail without echoing it. The unchanged transcript-redaction/count test and all affected job-drain, answer, failure, agent, transcript, and activity regression groups pass. The complete TUI rerun on that correction passed 3,176 tests, with zero failures and four ignored, in 385.87 seconds. Final production-file hashes still match the verified tree.

## Provider schemas and unavailable models

The subsequent investigation reproduced an independent transport defect: the OAuth adapters serialized Zod internals as tool schemas, and the next-step declaration bridge lost canonical Rust constraints through a partial conversion. KEEP after director review: preserve the Rust JSON Schema through declarations, convert local Zod v3/v4 tools at the provider boundary, and disable implicit strict normalization of optional arguments. Runtime/tool authorization and Rust input validation remain authoritative. Eight new regressions failed before the repair. Ten schema tests now pass, including real bridge-entrypoint tests with local provider responses.

One deliberate real Ask with the same selected GPT-5.4 model still returned HTTP 400. The metadata-only observer recorded model/support error markers. [OpenAI's current model documentation](https://learn.chatgpt.com/docs/models#other-models) confirms retirement for ChatGPT sign-in on August 31, 2026; the local coding-agent model cache omits GPT-5.4 too. Observed cost is zero and provider spend remains unresolved. No successful real response is claimed, and the older response body was not retained. The operator has been asked to select a current model for further live checks; no change has been made while that answer is pending.

The failure adapter now recognizes narrowly defined unsupported-model error shapes and passes only a canonical explanation through the existing provider-rejected metadata. Unknown/malformed bodies preserve the original HTTP class; raw messages never become durable detail. The TUI points to explicit model selection. A local protocol simulation on the rebuilt ordinary executable verifies the complete message and retained question at 80×24. The real and simulated sessions are separate and closed. At that checkpoint the static model picker still offered the retired entry; the subsequent pass below repairs its suggestions. A successful real Ask, full auth/cancel/resume, and all other broad acceptance items remain open.

Current focused verification: 116 bridge tests, three core failure-metadata tests, and ten TUI failure tests pass. The final repository quick gate, normal CRAP-risk gate, and CLI rebuild pass. The earlier 3,176-test full TUI checkpoint predates this small failure-detail change; no new full-suite run is implied. Verification receipts and the bounded self-review are under `hardening/oauth-schema/` in the private audit evidence directory. Changes remain uncommitted and no independent reviewer was launched.


## Current model suggestions and stable selection

KEEP after director review: update the static suggestions without redirecting legacy IDs, keep the saved model visible separately, bind the highlighted candidate by model ID, and preserve explicit activation. Four catalog regressions and one Enter-selection regression failed before their fixes. Further checks caught stale command completion and startup reasoning inherited from a suggested model; both are corrected. The nine current suggestions include distinct API-key and ChatGPT paths. Catalog membership and stored credentials are not claims of account access. Unknown and retired selections remain explicit and unchanged until the operator chooses another model.

The ordinary global command now shows the retirement explanation and usable controls at 120×36, 80×24 and 40×12. At the smallest size, scrolling reaches the last model while retaining its label, intended effort and complete Enter/Escape actions. Escape returns to Setup. Reducer checks also preserve exact model, target, shell draft, multiline Ask draft, Setup cursor and plan; Enter uses the highlighted ID after ordering changes. Numeric/alias compatibility and uniqueness checks pass. Terminal evidence is text/ANSI, not native screenshots, and no new model request was made. The saved-model question remains pending.

The first quick gate caught the existing model alias after it moved from a selector match into catalog data. The lint allowance now recognizes that exact standalone alias row only inside an approved model file containing the canonical public model ID; rejection tests retain checks for missing context, unrelated files and additional private references. No general private-name allowance was added.

At the model-suggestions checkpoint, the remaining source-confirmed problem was that Config moved an internal model cursor with Up/Down but its table marks the active model instead of that candidate, and the catalog may be offscreen. The repaired Setup picker does not fix this separate path. Provider-backed catalog discovery, model search, effective reasoning options, rich/streamed Answers, successful Ask/auth/cancel/resume and full phase acceptance also remain open. Verification and terminal receipts for this bounded pass are under `hardening/model-picker/`; final gate results are recorded in its revalidation receipt. These changes are uncommitted and reviewed by the director only.


Model-picker verification: 3,185 tests passed in the full TUI run, five stale explicit OAuth-switch expectations failed, and four tests were ignored. After changing those expectations only, all 39 OAuth tests pass, including the five original failures. The preserved assertions still cover exact target/phase/plan continuation, deferred-input binding, unchanged global selection where required, credential-store reprobe and redaction. Production Rust did not change after the full run; the slow phase battery was not repeated. The model-picker catalog/identity/renderer regressions passed in that full run. The final repository quick gate and normal CRAP-risk result are captured in `hardening/model-picker/REVALIDATION.json`.


## Config selection and returning from the chooser

KEEP after director review: remove the invisible Config model cursor and its duplicate application path. Config arrows and j/k now scroll the settings document. Enter in Navigate mode opens the shared ID-bound chooser without a settings mutation; explicit acceptance applies exactly the visible candidate. Config-origin cancellation, Back, reopening and explicit model commands restore Config’s scroll, input mode and navigation history while retaining drafts, target and workflow phase. Existing Setup-origin returns and explicit legacy model selectors remain supported.

Four new behavior tests failed before the fix: arrows did not scroll, opening emitted a persistence effect, and accept/cancel returned to Setup instead of Config. They now pass. The live ordinary executable verified identical Config body content before opening and after cancellation at a nonzero scroll offset. Acceptance then exposed a misleading inherited navigation hint beneath the chooser. A failing renderer test captured it; picker-owned controls now take precedence over the generic navigation announcement. The final picker group passes 185 tests. The earlier broad TUI rerun passed 3,197 tests, with four ignored and three unchanged slow phase-rendering matrices excluded; it was not repeated after the final hint change. Thirty-four Config-focused checks pass. Ordinary compilation caught two accessors restricted to test builds; their existing narrow router APIs are now available to the production restoration path.

Evidence, terminal/source/binary hashes, exact test exclusions and final gate results are under `hardening/config-model-selection/`. No real model was selected or invoked during terminal acceptance. The pending live-model question remains unanswered; provider-backed discovery, reasoning-option fidelity, rich streamed Answers, remaining fields/chrome, and full successful phase/auth/cancel/resume journeys remain open. Source edits are uncommitted and review is by the director only.


The final Config acceptance also checks the chooser’s own footer while its command field is active: Enter runs the command and Escape returns to the picker list; the footer no longer claims it will select a model. A second red renderer regression captured that conflict. The final 185-test picker rerun covers both hint corrections. No second broad TUI run is implied.

Removing the obsolete cursor module exposed a quality-reader bug: the private-context checker tried to read an unstaged deletion from Git’s tracked-file inventory. It now excludes only paths Git confirms deleted in the working tree. Tests prove that deleting the required ignore policy still fails and that other tracked private content is still rejected; all ten checker tests pass. The gate was not bypassed or disabled.


## Budget editor and precise cap disclosure

The previous Config checkpoint made progress; the broad goal remains open. A fresh ordinary-executable check reproduced ignored cursor movement, append-only text and paste, whole-draft Delete, and an offscreen budget field at 40×12. Six reducer regressions also found that typing `-5` saved a different amount (`5`) and reopening `0.00125` rounded the draft to zero. A constrained full-frame renderer test reproduced the hidden field.

KEEP after director review: reuse FieldEditor and give Budget the primary Setup body. Typing, paste, Delete, Home/End and editing chords operate on the visible cursor; arbitrary invalid characters remain visible until validation refuses them. A deliberate Enter or Ctrl+S saves only the session cap; an empty field unsets it while preserving the independent hard ceiling and durable config. Cancel preserves the Setup selection, plan, target, workflow phase and both drafts. Ctrl+C/Ctrl+D keep the existing exit/cancel ownership. Validation remains finite-positive and within the hard ceiling. Extracted pure parsing and application handlers replace the duplicated large picker methods.

The field shows the current session amount and hard ceiling, a cursor-following viewport, complete validation and real save/cancel controls at 40×12/80×24/120×36. A subsequent live save exposed another precision defect in Setup’s summary (`$0.00 session cap` for `0.00125`); a separate red test reproduced it. Both enforced and over-ceiling receipts now preserve the amounts’ identity.

Verification: six pre-fix editor failures, one constrained-renderer failure and one saved-summary failure. The final focused checks pass 16 Budget tests and 54 Setup tests. Surrounding regression groups pass 185 picker, 28 paste and 22 quit tests; the broader budget group passes 53 tests with three performance tests ignored. Those surrounding groups preceded the final summary-only formatting correction. No complete TUI rerun is claimed in this pass. One removed test-helper reference caused an intermediate compilation failure; its narrow call site was migrated without weakening the assertion. Normal CRAP-risk passed during development. Final build, terminal, quick-gate and source-integrity results are recorded in `hardening/budget-editor/REVALIDATION.json`.

Live acceptance uses only temporary targets and terminal text/ANSI. No provider request, model selection, scan or persistent-config mutation is needed for this flow. Review remains director-only, not independent or post-commit. Changes are uncommitted.

Open finding from the same live check: the existing quit overlay shows no disclosure body at 40×12 and reports `1–0 / 16` (capture `05-before-quit-40x12.txt`). This contradicts a blanket small-frame quit claim even though the prior 80×24 repair remains verified. Fix that geometry next, then continue planning-option editing, remaining focus paths, response presentation and successful provider/full-phase acceptance.


## Authorized GPT-5.5 OAuth and useful Map Ask

The operator explicitly requested OpenAI OAuth with GPT-5.5, resolving the earlier pending selection. The operator-owned global model is now GPT-5.5 over OpenAI OAuth with medium reasoning. The existing stored OAuth connection works; no new API key, browser login, or model substitution was needed.

KEEP after director self-review: normalize public OAuth aliases at the shared parser, offer GPT-5.5 as a distinct OAuth choice while retaining all prior IDs, and forward selected effort through the Rust next-step envelope and the OAuth request body. Real requests confirm the exact model and medium reasoning.

Live checks also found that generic Ask passed no Map context while the Map was visible. KEEP: compose the existing screen receipt with a bounded model slice from the already captured immutable revision. It carries the system description, selected component/DFD element, nearby flows and linked security context, under the existing untrusted-data fence and byte cap. It does not read a newer revision during composition or replace another phase's context. Two regressions failed before the repair; final tests also cover DFD selection in zoom.

A real model-backed Map on six unchanged Rust source files completed and persisted a four-node, three-flow DFD. The ordinary command reopened the saved Map and reused the saved model. A subsequent real Ask on the repaired build correctly describes the mapped crate. No generated threat is promoted to a verified finding.

Remaining issues from this same run: two unit-test deserialization examples became high-exposure entry points and model hypotheses; completion returned to an empty-looking Setup before `workbench` exposed the ready result. Rich streaming, constrained quit, remaining fields, cancellation, conversation resumption and full phase acceptance remain open. [Detailed report](OPENAI_OAUTH_2026-09-08.md), [evidence](~/clone-references/kuzushi-ux-audit-2026-09-07/hardening/openai-oauth-live/REVALIDATION.json).

The follow-up check caught a second Map-context mismatch: on restart the renderer selects Summary when the stored gallery page is outside Map's page set, while Ask used that hidden stored page and reported no selected component. The shared model-context projection now uses the same effective Map page as the renderer. A red regression reproduces the untouched startup state; the final live answer names the selected component, its exact flow, neighbor and trust boundary.


## Rust test-scope grounding correction

Director proposal/refutation KEEP, bounded to explicit Rust test-only source scopes and cached evidence reuse. Shared inventory/surface projection excludes the observed descriptor unit tests before ranking and grounding. Current-policy metadata retains production surface identity and participates in catalog authentication; old Rust rows require context/catalog rebuilding. Real GPT-5.5 medium execution on the same six unchanged source files produced zero catalog/model entry points and a saved, reopenable Map. The broader test/reachability problem remains partial. The next P1 is insufficient source-body context in default model grounding. Full evidence, limits and verification: [test-scope revalidation](RUST_TEST_GROUNDING_2026-09-08.md). The broad acceptance checklist remains open.


## Foreground Map completion and acceptance

The completed foreground Setup Map now opens its exact unresolved result. Background/manual ownership, unrelated origins, draft text and input mode retain their existing policy. A real GPT-5.5/medium run verified the destination at 80×24 and 120×36.

That run exposed a second failure: Use map recorded intent but could not advance because entry extraction and automatic recommendation omitted authenticated source identity. Shared source receipts now cover those producers. Selection consults the existing core reuse gate, refreshes before writing, and preserves the displayed attempt ID. Missing/stale identity keeps the result inspectable and requires rerun; old receipts are not rewritten.

Final live verification: a fresh Map has one authenticated identity across all four runs; reopening and explicitly accepting its unchanged result on the final build advances to Scan, and a further restart preserves Map completion. Thirteen destination/acceptance tests, 52 phase-result tests and the focused core groups pass. Source/model hashes remain unchanged and acceptance causes no new provider call. See [the detailed completion report](MAP_COMPLETION_2026-09-08.md) for the two-build provenance, initial failed acceptance, gate receipt and remaining limits. The broad checklist stays unchecked.


## Constrained quit disclosure and measured paging

Director review KEEP: share actual disclosure geometry with keyboard scrolling, expand to the full frame when the normal body is unreadable, pin complete exit/stay choices, and clamp before movement. Two initial full-renderer regressions reproduced the empty body and end-offset debt. Final quit tests pass 18 cases, including five new full-shell tests for small/ordinary frames, complete paging, resize and draft/origin restoration.

The real 40×12 terminal now pages 1–8/15 → 8–15/15 and back after 20 extra Page Down presses. Resizing to 80×24 retains the contextual dialog; Stay restores the exact unsaved Budget value. Explicit confirmation exits normally. Live planning-option checks on the same executable reproduce ignored Left and whole-draft Delete; both trials were canceled. [Detailed report and verification](QUIT_VIEWPORT_2026-09-08.md). The broad checklist remains open.


## Planning-option editor follow-up

Proposal and director self-review: KEEP shared FieldEditor state, full KeyEvent ownership in the active Setup Plan/phase planner, descriptor-backed validation, exact draft/error retention and a primary editor body. KEEP shared geometry for paged validation after two red narrow-renderer tests. Saving inside the field changes only the session option and never launches work; the existing persist action outside editing stays separate. Remove the obsolete clipped suffix-cursor renderer.

Status: implemented and sequentially accepted in Setup. Left insertion, forward Delete, cancel, invalid-value recovery, Ctrl+S session save, quit/Stay cursor restoration and 40×12/80×24/120×36 Unicode paste pass on the rebuilt executable. Long validation reaches all 18 rows and recovers immediately from repeated end paging. The model configuration and six real source files are unchanged, no tool runs were created, and the owned session exited normally. Planning 97, picker 185 and keybinding 32 tests pass (overlapping groups); phase-planner origin and Shift+Enter are reducer/renderer checks. [Evidence and limits](PLANNING_OPTION_EDITOR_2026-09-08.md).


## Completed-answer Markdown reading

Proposal and director self-review: KEEP a CommonMark event parser, pure styled-line projection, display-width wrapping, preserved code indentation and link destinations, aligned wide tables and labeled narrow records. Reuse the existing conversation and document cache, deriving plain output from the same lines. Preserve raw questions/errors and raw response storage; do not turn model text into executable links or HTML. Keep excessive nesting readable through literal rendering.

Live amendment KEEP: the first ordinary-executable check exposed only two answer rows at 40×12 because generic footer hints duplicated pane controls. The new red geometry regression required five rows. Compact Answers now suppresses those duplicates while retaining status, captured context, position and complete reply/workspace hints; workspace focus restores its normal chrome.

Status: implemented with nine parser tests and four new integration checks. The final Answer group passes 43 tests and Chrome group 15. Two sequential local protocol checks beside the existing real Map verify Markdown, complete response reading, focus/scroll preservation and an unsent Unicode reply across resize. Final 40×12 reading needs 14 pages instead of 34 for the same 67 rows. Six source files, seven protected model files and the saved configuration are unchanged; the final owned terminal exits with status 0. These are local display checks, not new provider requests. Streaming and lexical syntax highlighting remain open. [Evidence and limitations](ANSWER_MARKDOWN_2026-09-08.md).


## Incremental Ask response delivery

Proposal and director self-review KEEP: use an ephemeral runtime text observer,
explicit bridge response frames, bounded incremental OpenAI OAuth decoding and
nonterminal job events. Preserve exact model selection, typed terminal results,
usage, tool identities, supervised cancellation and the legacy single-JSON bridge.
Keep public text separate from reasoning and diagnostic metadata. Reliable queue
delivery prevents missing fragments; a new model attempt replaces its preview.

Status: implemented. Local terminal completion/cancellation, compact reading and
a held Unicode reply pass. Two real GPT-5.5 OAuth turns complete; the follow-up
shows visible text at 2.91 seconds and finishes at 4.51 seconds. Partial text stays
incomplete after cancellation and is excluded from completed conversation output.
Six source files, seven protected model files and the saved configuration are
unchanged. All owned terminals exited with status 0. The broad checklist remains
open; Anthropic OAuth streaming, real-provider cancellation and the full phase
workflow still need acceptance. [Detailed evidence](ANSWER_STREAMING_2026-09-08.md).


## Scan completion and acceptance checkpoint

Three observed blockers are corrected: foreground completion returning to the old planner, model Scan results missing source identity, and an absent offensive-hunt finding event producing a zero-count phase receipt. The old attempt remains unchanged and unaccepted; a new execution on the same six files carries matching source receipts, completes both selected tasks, records two new observations and offers Review. Explicit selection and restart retain the two unverified candidate groups. The normal CRAP-risk gate passes for 224 cumulative changed files, the quick gate passes all ten steps, and focused completion/result and module/receipt tests pass. This is a dirty-tree checkpoint, not a release or full interaction completion. [Details and remaining findings](SCAN_COMPLETION_2026-09-08.md).

## Review persistence and accepted all-rejected branch

Three shared-path defects are corrected: source-bound triage receipts, applicable finding-local decisions (including cached-value scope), and current-observation selection with source history retained. The real GPT-5.5 OAuth rerun classified two candidates as false positives, persisted matching source hashes and was explicitly accepted. It opened Report; 80-column restart retained Review completion and both decisions. Focused findings/triage/Review/refresh tests and all ten quick gates passed. [Full evidence and limits](REVIEW_WORKFLOW_2026-09-08.md).

The broad checklist remains open. Next observed repairs: result action says Commit & Prove but opens Report, result-owned n conflicts with the queue's page hint, and Report displays campaign-only zero spend as if it covered the metering-incomplete module runs. Report export/retry, actionable Prove/Fix and full decision-history reading remain unverified. No findings or proof were fabricated to complete those branches.


## Report recovery and export checkpoint

Director KEEP: derive result continuations from current journey truth without adding withheld actions; share card/footer bindings; replace Report's campaign-only spend claim with explicit recent cost coverage and unfiltered review counts. KEEP the shared destination editor, independent save/cancel, format-specific session paths, contained defaults, paged receipts and quit/Stay preservation. The final live caption also names Escape's actual Return behavior.

Verification: 42 Report, 55 phase-result and 32 keybinding tests pass (overlapping selections), together with the focused remap/unbound footer test. All six real-ledger exports contain both automatic false-positive findings; identity/fingerprint and bundle hash readback checks pass. Four sequential J54 runs retain the failed adjacent Escape/Home attempt and successful paced 40-column rerun. Source, Map, workflow, existing receipts and OAuth/model config hashes are unchanged; no new model run was created. All ten quick gates pass on the dirty tree. Full evidence and limitations: [Report workflow](REPORT_WORKFLOW_2026-09-08.md).

No broad acceptance checkbox is complete. Aggregate spend, report persistence/reveal, rapid escape handling, remaining fields/copy, cancellation/resumption, fresh auth and actionable Prove/Fix still need work.


## Real Ask cancellation and restart recovery

KEEP after director review: persist a typed public conversation checkpoint in the existing operator-owned, redacted transcript, with its target/revision/Map/policy binding. Recover asynchronously with limits and generation checks, retain interrupted/canceled status, restore submitted failed questions without overwriting a newer draft, and honor explicit clear. Reuse the existing fenced history projection; incomplete preview text stays out of model input. Recovery never changes model selection or starts a request.

Status: the real cancellation check passed and exposed an empty Answers pane after restart. The repaired path passes sequential 80-column completed-answer recovery/follow-up/clear and 40-column cancellation/restart/edited retry. Six real GPT-5.5 OAuth requests use medium reasoning. Focused Answer, Ask and transcript checks pass, as do the normal CRAP-risk and all ten final quick gates. Source/Map/accepted-attempt/old-receipt/export hashes and saved model configuration are preserved. Five target bookkeeping files change with the new runs; the four prior Review decisions remain. [Full evidence, limits and original failures](ASK_RECOVERY_2026-09-08.md).

The ten broad acceptance items remain unchecked. Multiple saved-conversation selection, hard-termination recovery, large history stores, fresh/expired auth, concurrent Run/Ask, full batch and actionable Prove/Fix acceptance, aggregate spend and the remaining fields/copy still need work.

## Unresolved Review and pre-launch model disclosure

The labeled canary produced four real scanner candidates. Review initially acknowledged local unsafe code but rejected every candidate because callers/entry points were unavailable. The Boolean-only analysis now admits unresolved assessments, and an implausible-trigger refutation without an inspected call path remains needs-review. Six new regression tests and a real explicit GPT-5.5 OAuth retriage verify the change: four needs-review outcomes, prior rejections preserved, same source identity, and no phase advancement after acceptance/restart. Setup now exposes model and auth in the ready rows at 40/80/120 columns. The broad checklist remains open. Prove still offers local reproduction without actual backend readiness and needs shared dispatch/runtime/result-acceptance review. [Full evidence and limits](UNRESOLVED_REVIEW_2026-09-08.md).

## Real model Prove acceptance

One real GPT-5.5 static verification is selected and survives restart without becoming runtime proof. Completed Prove results now show their assessment before selection at 80 columns, and required live-screen checks stop mistaken automation launches. Narrow result reading, local reproduction and the broad checklist remain open. [Evidence and limits](MODEL_PROVE_2026-09-08.md).

## Trace results and phase ownership

Complete Trace outcomes now recover their questions, notes, run identity and
source status, including zero-step results. Trace no longer shadows a pending
verification or offers supporting evidence as a selectable proof set. A fresh
GPT-5.5 OAuth expansion and 80/40-column restart checks preserve the original
verification, selected proof and raw workflow history. Nine ownership
regressions and all ten quick gates pass. The live execution journey remains
partial: the immediate view needs its durable receipt refreshed, and Escape
first dismisses the completion notice. These are the next interaction repairs.
The ten broad acceptance categories remain open.
[Evidence and limits](TRACE_RESULT_OWNERSHIP_2026-09-09.md).

## Immediate Trace receipt and one-key return

The saved Trace run/source receipt now refreshes after successful persistence.
Informational and successful notices no longer consume the reader's Escape;
banner hints use the same key-ownership decision. The real GPT-5.5 retry and
80/40-column restart checks pass, preserving both ledgers and all selected
proof. Eight new regressions and all ten quick gates pass. The first live
failure is retained: missing source-build helpers were restored by building
the workspace, and an old receipt match was rejected as insufficient evidence.
[Details and limits](TRACE_COMPLETION_2026-09-09.md).

All ten broad acceptance categories stay open. The failed trial exposed the
next repair: generic completion notices replace actionable failure guidance.

## Failure notice retained; Replay reading still partial

Receipt publication now retains the current actionable error/warning and does
not downgrade failed outcomes. Six new regressions, 62 surrounding completion
tests and all ten quick gates pass. An isolated real-adapter failure at 80
columns retains the complete build remedy and the expected two-stage
alert-dismiss/reader-back behavior. Sources, prior runs, workflow and proof
remain unchanged. [Evidence and limits](FAILURE_RECEIPT_NOTICE_2026-09-09.md).

The follow-up reading checks expose the next concrete defects: Replay clips
the failure remedy horizontally, and its “Esc nav mode” hint actually returns
to Prove. Correct those and verify the existing failed run at 80/40 columns.
All ten broad acceptance categories stay open.

## Saved Replay reading and return

The failed-run reader now wraps complete projected messages, pages by its visible body, and moves away from the end immediately. Escape names the actual back/dismiss action; background-work cancel labels and Answers focus retain priority. Eight focused regressions, normal CRAP-risk and all ten quick checks pass. Sequential installed-launcher checks at 80×24 and 40×12 expose the complete saved failure remedy and return to the same pending verification. No new run, workflow selection or proof was created. The first narrow trial exposed a driver limitation and is retained as unsuccessful setup. [Evidence and limits](REPLAY_READER_2026-09-09.md).

Next: inspect full Activity failure-detail access and the narrow failure notice. Live concurrent-work recovery and the proof-backed Fix/re-verification/Report journey remain open. All ten broad acceptance categories remain open.

## Run Focus scrolling; compact failure reading remains partial

Run Focus Output now recovers from the top and overscroll immediately, pages by the actual pane, and names the real Ctrl+C action. Six new reader regressions, surrounding Activity/Run Focus/Replay tests and all ten quick checks pass. The 80×24 live failure journey passes. At 40×12 the text is reachable, but only one content row is visible; the full remedy takes many pages, the header hides the run id, and the notice truncates both remedy and dismissal hint. That journey remains partial, with its failing check retained. [Evidence and limits](ACTIVITY_READING_2026-09-09.md).

Next: compact Run Focus hierarchy and useful reading space, followed by complete error detail and visible dismissal. Preserve the existing reader fixes and all accepted workflow/proof state. All ten broad acceptance categories remain open.

## Compact failed-run reading and complete error access

Short Run Focus screens now retain complete run identity and five Output content rows instead of one. The full-message route exposed a real Logs paging defect; measured wrapped-row bounds, page movement and tail release now pass reducer/render checks and sequential 40/80-column failure journeys. Both final runs complete 24 machine checks, and all ten quick checks pass. Director review remains partial: Keymap shows one row at 40×12, and Trace still advertises Esc back while an error owns Escape. No previous artifact, selected proof, source or model configuration changed. [Evidence and next repairs](COMPACT_FAILURE_READING_2026-09-09.md).

Next: usable narrow Keymap reading and consistent error-owned Escape hints on Trace. All ten broad acceptance categories remain open.
