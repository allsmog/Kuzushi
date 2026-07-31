# Kuzushi TUI dogfood feedback

## Audit 1 — monorepo / edge-gateway walkthrough

Date: 2026-07-22
Build: release, main @ d632466e (+ local uncommitted WIP)
Target: ~/monorepo, then ~/monorepo/platform/src/acme/edge-gateway
Session: interactive walkthrough via tmux; feedback recorded verbatim as given.
Pruned 2026-07-22 after verifying fixes in 3060c3de..d632466e (see "Fixed & removed" at bottom).

## Feedback

1. **Map phase / first-run flow**: On a very large monorepo (~/monorepo), the first "NEXT ACTION" card pushes threat-model generation. User wants the app broken down into logical modules FIRST — module decomposition should be the entry point for big repos, before threat modeling. (a4b6d834's breadth-first budget spreading helps fidelity but the module-decomposition entry point still doesn't exist.)

2. **Progress indication gaps** (user asked "does it give adequate indication?") — mostly yes, with gaps:
   - Good: named stages with counters, "last progress Xs ago" heartbeat line, ✓-trail of completed stages, stall watchdog exists at all. The context:build hashing false-stall is now fixed (stage 6/6 + observer heartbeat landed).
   - Still open: the "⚠ NO PROGRESS SIGNAL" watchdog fires during long single model calls — observed again 2026-07-22 on edge-gateway threat-model:build ("NO PROGRESS SIGNAL for 1m43s · Ctrl+C cancels") while a healthy 213K-char synthesis query was in flight. A model call should count as live (e.g. show "query in flight Xs" instead of escalating). Other gaps: no ETA or per-stage progress fraction; "cost unavailable / cost not recorded / metering incomplete" repeated 3× on one screen; task pane truncates labels heavily at 120 cols; HEALTH pane wording ("Progress: complete" mid-run); two task rows for one logical operation.

3. **Result-card resolution keys dead / Tab hijacks context** (observed on ~/monorepo with a stale prior engagement; not yet re-verified there post-fixes): advertised card keys (`n/u/o/r`) did nothing in Navigate mode, Tab teleported from the Map walkthrough into a Review-phase resume planner, and the card rendered literal `\n` escapes in its first summary line. On edge-gateway the keys work. Related mode-flip papercut seen again 2026-07-22: Esc's meaning oscillates between "to Navigate" and "to Prompt" depending on hidden state, and single-key presses routinely land as prompt text ("q uickstart", "r eport") — cost 3 retries to resolve a prerequisite card. Card keys should be modal (captured regardless of prompt/navigate mode), which the prereq card already does — result cards should match.

4. **Stale prior engagement hijacks the fresh walkthrough**: With yesterday's engagement persisted (Map ✓ Scan ✓, 1 finding), every generic navigation lands back in its Review resume planner: (a) `next` typed on the MAP page — whose own hint row says "next continue Map" — dispatches the *derived-phase* (Review) planner instead of continuing Map; (b) Esc-cascade from the planner dumps you onto Prove, not back where you were. Need an explicit "start fresh pass / re-map this revision" affordance, and `next`'s label must match what it will actually run.

5. **Transient-failure recovery, remaining half**: In-place transport retries landed (d632466e: 5 attempts for 429 with 2/5/10/20s backoff + Retry-After, 3 for other transients) — right first half, verified live on edge-gateway threat-model:build. Remaining: (a) if all attempts exhaust, the run must still be CONTINUABLE — checkpoint completed stages/agent turns so the failed-result card's retry resumes from the failure point instead of re-running the whole tool from scratch. User: "there should be able to continue if it fails on five." (b) Polish: the 429 error message rendered twice, concatenated to itself, in the failed result card (fix unverified — old ledger records still render doubled).
   - **Confirmed end-to-end 2026-07-23 — the continuation machinery exists on disk but no RUN path consumes it.** The failed agentic-sast run (tool-…9c6394cd3afa) wrote a full failure handoff: `failures.json` carries `failedStage: agentic-sast:scan`, artifact inventory, recovery options, and a ready-made `fallbackPrompt` that literally begins "Continue the failed Kuzushi run for agentic-sast:scan…". The only consumers are soft: the chat view renders handoff rows (failure_handoff_lines.rs) and `ask agent` prepends the fallbackPrompt to operator questions (agent_prompt.rs) — informational/conversational, not a resumed tool run. There is no "continue failed run" ACTION on the card or planner. After the bridge fix landed, re-running from the Scan planner minted a brand-new single-tool run for the OTHER step (threat-hunt) and the failed run was never continued or re-attempted. User (again): "well it should've been able to continue no?"
   - **Planner resume state inverts after a partial phase**: returning to the Scan planner after threat-hunt completed, the just-COMPLETED step is still pre-checked RUN while the FAILED step (agentic-sast) is reset to SKIP. Enter would re-run the finished step and skip the broken one — the exact opposite of continue. (Same ledger-blindness family as item 9's stale checklist.)
   - **Run-focus header mixes runs**: the live threat-hunt run focus showed "0/6 done · 2 running · 3 ! failed · 1 ⊘ skipped" — but the 3 failed rows belong to the PREVIOUS run's agentic-sast tasks, rendered inside the new run …be2bcb28's header counts as if they were its own tasks. Task rows/counters must be scoped to the run being focused.

6. **`run <tool> {}` JSON-argument command style is terrible navigation UX** (user's words: "a terrible way of navigating"). Requiring operators to type raw tool invocations with a JSON literal — and erroring with "run input must be JSON. Next: run <tool> {}" when the braces get mangled — is developer-console ergonomics, not operator ergonomics. The advertised affordances (result-card keys, NEXT ACTION cards, `next`) should be the reliable path to every common action, with `run`+JSON as an escape hatch only. Note: the failed-card `r Run again` drafting the full JSON into the prompt for review-then-Enter is a decent pattern — but the draft is unreadably wide and still exposes raw JSON. Related: Setup's CTA says "Enter Start Map to commit" but Enter activates whichever row is focused (Target row → target picker loop).

7. **DFD viz scene is display-only and lossy — hidden content is unreachable in the TUI**: On edge-gateway (13 nodes / 11 flows) at 120x36, the GATEWAY zone renders 4 of 9 nodes and collapses the rest to "+5 more" with NO way to see them: j/k/arrows/Enter/Space/+/-/PageDown do nothing (only Tab cycles pages, Esc/q exits). Node labels truncate mid-word ("Internal SaaS servic", "Bluejay│authorizat") and flow edges are drawn THROUGH node boxes, overwriting label text ("apping ser" is all that survives of "Account mapping service"). The 11 flow descriptions and per-flow trust-boundary tags exist in threat-model.json but are not surfaced anywhere in the scene — no node/edge selection, no detail pane, no flow list. The complete DFD should be visible through the TUI: scroll/pan or paging within a zone, a selectable node/flow inspector, and edge routing that doesn't clobber labels. Nit: the scene footer says "7 boundary crossings" but 8 flows carry trustBoundaryIds in threat-model.json — one crossing is miscounted or silently dropped.

8. **Threats view (`threats stride` / `threats stories` / `threats summary`) — data inconsistencies and unreachable content** (edge-gateway, 10-threat model, 2026-07-23):
   - **Stories list is unscrollable**: header says "ATTACKER STORIES · 10" but only 8 rows fit at 120x36 and NOTHING scrolls — footer advertises "PgUp/PgDn scroll" (does nothing), and j/k in Navigation mode ("view keys active") also do nothing. T9/T10 are unreachable in the TUI. Same disease as the DFD "+5 more" (item 7).
   - **Tab-bar number keys are a footgun**: the view header advertises "1 STRIDE  2 STORIES  3 SCOPE  4 SUMMARY  5 VERSIONS", but pressing `1` in prompt mode drafts `model 1` — a MODEL-SWITCH command — into the shell prompt. One reflexive Enter after a advertised tab key would silently change the execution model. Tab keys must be captured by the view (or the tab bar must not advertise bare numbers).
   - **UI threat IDs disagree with the artifact**: the stories view renumbers threats positionally (T1..T10 in severity order), but threat-model.json `id`s are creation-ordered (T1,T2,T6,T5,T7,T8,T9,T3,T10,T4). So UI "T3" (DEK wrapping, CRITICAL) is JSON "T6", and UI "T8" (sleepTime DoS) is JSON "T3". Cross-referencing a TUI threat against the exported artifact — the stated export path — is broken. Show the artifact's `id`/`stableId` in the list.
   - **Summary tab counts wrong / mislabeled**: "assets 13" — the JSON has 6 assets; 13 is the DFD *node* count. Also "narrative summary unknown" while threat-model.json `summary` exists (it's the structured byCategory/bySeverity rollup — either render it or don't imply the model lacks one).
   - **STRIDE rollup is 6 rows + 18 blank lines**: 10 threats collapse to one truncated example description per category ("…" mid-word), with no way to expand a category into its member threats, while most of the screen is empty.
   - Fresh result cards still render literal `\n` escapes (confirmed on the completed threat-model card, not just failed ones — see item 3).
   - **Methodology identity crisis (PASTA vs STRIDE)**: user's NL request was "build the PASTA threat model"; the run completed as "Method: STRIDE · Provider: randori-pasta · Stages: s1, s2, s3, s4" (PASTA stage names, STRIDE method label), threat-model.json records `methodology: "stride"`, and the phase planner then lists "Build PASTA threat model — not built yet" as a SEPARATE unbuilt row next to the cached STRIDE one. Either the NL router silently substituted STRIDE for the requested PASTA, or the artifact mislabels a PASTA build as stride — both paths break trust. The planner, the result card, the artifact, and the NL router must agree on one methodology vocabulary.
   - **Capabilities view "press Esc, then e for expert engines" doesn't work** (repro'd 2×): Esc closes the CAPABILITIES popup entirely (back to previous view), so `e` lands in the shell prompt as an "e xport" draft. Advertised keystroke sequences must survive their own first key.

9. **Phase planner: stale checklist after running steps + contradictory phase headers + hollow threat-intel** (edge-gateway, 2026-07-23):
   - **Stale checklist re-render**: checked "Build PASTA threat model" + "Threat intel (CVEs)" in the Map planner, Enter → both ran (PASTA model persisted, threat-intel/candidates.json written). Returning to the planner afterwards (Esc from the auto-opened DFD viz) shows the SAME checklist with both steps still "RUN · not built yet" and footer "Enter: run 2 new steps" — pressing Enter would double-run two model-backed steps. The planner must re-derive outcomes from the ledger on re-entry/re-render, not replay its creation-time snapshot.
   - **Contradictory phase labels on one screen**: planner title says "── SCAN ── phase 2 of 5" while the tab row on the SAME screen shows "[1 Map ●] 2 Scan ○", the banner says "phase map starts a fresh Map pass", and the status line says "workbench · Map 1/5". Four phase indicators, two answers.
   - **threat-intel:discover is an empty stub on Bazel-managed Go**: output candidates.json has cves:[], packages:[], and a note telling the operator to populate from OSV/NVD and feed threat-intel:harvest. On a Bazel monorepo module (no local go.mod) it should fall back to BUILD.bazel go deps or the workspace module graph; and the planner row "Threat intel (CVEs)" reads as if it will research CVEs — the discover→harvest split isn't surfaced anywhere in the flow.
   - **PASTA cache detection is broken even on a freshly derived planner**: after the PASTA build persisted (threat-model.json methodology:"pasta", threat-model-pasta/normalized-threat-model.json on disk), a brand-new `next` planner correctly flips threat-intel to "REUSE · cached" but STILL shows "Build PASTA threat model — RUN · not built yet", pre-checked to run. Every planner pass would re-run the most expensive model-backed step. The row's built-detector doesn't recognize whatever artifact the PASTA build actually writes.
   - Completing threat-model:build auto-opens the full-screen DFD viz scene, interrupting whatever the operator was doing (second occurrence; fine as a notification, jarring as a forced scene switch — and it hid the run receipt for the parallel threat-intel step).

10. **Scan planner defaults are inverted**: the Scan phase pre-checks "Scan for secrets" (secret-scan:scan) alongside the threat-model-driven hunt, while the model-backed analyses ship unchecked. User direction: secret-scan and semgrep should NOT be defaults — the model-backed steps (agentic SAST review, threat-model-driven hunt) should be the pre-checked defaults. Rationale from the session: right after Map completes, the workspace has a fresh threat model, and agentic-sast consumes it directly (threat-model-digest handoff in build_prompt.rs) — a threat-informed hunt is the natural next action; secret/semgrep scans are cheap add-ons, not the spine of the phase.

11. **`bridge_internal` is an observability black hole**: agentic-sast:scan died with "Bridge operation failed; raw error details were suppressed." — and the raw error is discarded EVERYWHERE: not on bridge stderr, not in the run's failures.json (which just re-quotes the public message), no env-var debug escape hatch. Root-causing required an out-of-band capture shim on the bridge process. Actual cause (found via the parallel session's debugging): @langchain/anthropic's `validateInvocationParamCompatibility` throws client-side when a tool pins `temperature` on adaptive-thinking-only models (claude-orchid-5 et al.) — no HTTP call ever happens; `errorClassFromShape` doesn't recognize the shape → bridge_internal. Fix for the temperature bug itself is already in WIP (TEMPERATURE_LOCKED_MODEL_PREFIXES guard in model.mjs). Remaining asks: (a) persist the raw error (sanitized) into the run ledger/failures.json alongside the public message; (b) classify SDK client-side validation failures as their own errorClass with an actionable message; (c) surface WHICH stage/call failed in the result card instead of a bare bridge_internal.

12. **offense-review:threat-hunt silently drops actor findings — run reports 0 findings while the artifacts contain real ones** (run tool-…be2bcb28, edge-gateway, 2026-07-23). The 3 Carlini actors all completed under the fixed bridge; per-actor artifacts show AMS: `{"findings":[]}` but Appliance_cluster_agent (7,847 out-tokens) and Internal_SaaS_services (7,711 out-tokens) each returned structured findings with file:line evidence (bluejay_auth cookie/account cache-hit bypass; RouterRPC ForwardRequest dispatch on `in.Uuid` with no ownership check). Yet: trace ends `carlini-threat-hunt:run complete · 0 findings`, run.json `findings: 0`, report.md "No report was recorded for this run", and no `.kuzushi/findings.json` was written. The compose → tool-call → defender-critic subtasks that the run-focus pane displayed as the plan NEVER ran — llmCalls contains only the 3 initial actor queries, then the run flips straight to done. **Root cause found (code read, not patched)**: a prompt↔normalizer schema mismatch with silent drops. The actor prompt only says "Return exactly one JSON object and no prose. Use {\"findings\":[]} when there are no concrete exploitable findings" — it NEVER declares the per-finding schema (no mention of filePath/startLine/message anywhere in the 205K-char prompt). But `normalize_findings.rs::carlini_finding_from_object` hard-requires `filePath`/`file_path` on each finding (`carlini_location(...)?` → `None` → finding skipped with no log). The model returned 5 well-structured findings (title, severity, evidence[], source, sink, trace — file refs inside evidence strings), none with a literal `filePath` key, so all 5 were silently discarded → "0 findings". Fixes needed: (a) declare the exact finding JSON schema in the prompt (or use structured output enforcement like other paths do); (b) normalize leniently — fall back to extracting file:line from evidence/source/sink fields; (c) NEVER drop a finding silently — log/trace each rejected object with the reason, and surface "N findings rejected by schema" in the receipt. Secondary: "compose · tool-call · defender-critic" is just a static trace LABEL on the actor scope (run_carlini_threat_hunt.rs:458), rendered in the TUI as if they were real pending pipeline stages — misleading; there is no compose or defender-critic stage in this path at all.

13. **Findings tab needs human-enjoyable search and filter** (user direction, 2026-07-23): "in the findings tab we should be able to search and filter for certain findings in a human-enjoyable way." Operators triaging a scan need to slice findings interactively — free-text search across title/message/evidence, and filters on the obvious facets (severity, source module/tool, file path, actor, confidence, status open/verified/rejected) — without dropping into `run <tool> {}` JSON or grepping .kuzushi/ artifacts by hand. "Human-enjoyable" is the bar: incremental type-to-filter, visible active-filter chips, counts per facet, zero-JSON. (Compounds items 7/8: list views that can't scroll, search, or filter make every dataset >1 screen partially unreachable.)

## Fixed & removed (verified in 3060c3de..d632466e + local WIP)

- ~~context:build silent ~3min hashing → false NO PROGRESS SIGNAL~~ — fixed as suggested: `ContextBuildStage::RegisterTreeIdentity` stage 6/6 "registering tree identity", `register_workspace_tree_identity_with_observer` heartbeats in both callers (build_context_snapshot.rs, scan_prepare.rs).
- ~~429 kills the run with no in-place retry~~ — fixed by d632466e bridge retries + WIP transport_retry (classified rate-limit schedule, Retry-After honored, run state kept). Remainder tracked as item 5.
- ~~Language detection wrong on monorepo (reported Python for a Scala/Bazel monorepo)~~ — root cause: `.scala`/`.sc`/`.thrift` missing from the extension table entirely (language_for_path.rs); added in a4b6d834 with breadth-first inventory walks. Will show correct on next context regen.
---

## Audit 2 — opencode review

Audit date: 2026-07-22
Terminal: tmux 3.6a, 120x36
Kuzushi build: `0.24.0-alpha.8`, `6ab75576b328ab8c1747ac068a8668d75d0a2597+dirty`, release
Target: `/private/tmp/kuzushi-opencode-review.HPIrp9`, opencode `411eff73f026d4950c07947c4d983788cb615baa`

## Findings

1. **[Display / workflow] Setup's model picker hides the requested supported model.** With global model `openai-codex:gpt-5.4`, the Setup picker showed GPT-5.4, GPT-5.5 mini, and the two Anthropic choices, but omitted `openai:gpt-5.5`. The Config screen immediately afterward showed the complete list, including row 1 `openai:gpt-5.5 · xhigh`. Reaching the requested model therefore took two routes: one unsuccessful picker attempt and the `model 1 xhigh` command workaround. The persisted operator config correctly became `model = "openai:gpt-5.5"` and `thinking_level = "xhigh"`. Root cause: `visible_model_choice_indexes` seeds the preferred OAuth index and then indexes `1..4`, so index 0 is dropped whenever OAuth GPT-5.4 is preferred (`crates/kuzushi-tui/src/app/settings/model_choices.rs:78-99`); the picker consumes that filtered list (`crates/kuzushi-tui/src/renderer/views/onboarding/model_picker.rs:4-7`). Suggested fix: mirror the Config model table's full-catalog pattern—show every `MODEL_CHOICES` entry and only reorder/highlight the preferred item, using the existing visible-cursor translation rather than filtering a valid model out.

2. **[Display / workflow] Map-plan options are implementation-shaped and the layout changes under the operator.** Operator feedback, verbatim: "also the plan options should be presented to be pleasant to select for a human". At 120x36, `context:build` initially had a useful two-pane layout, but option rows exposed raw keys such as `sampleLimit` and `enrichment adv`, and the resolved input was truncated to `input {"discovery":"auto"...`. Moving from a deterministic task to STRIDE/PASTA caused the entire options pane to disappear and the screen to fall back to a compact full-width task table. STRIDE and PASTA then differed only by their names; their methodology/output implications were not explained. Root cause: the expanded renderer builds a master/detail view and then abandons it whenever the selected row's extra prompt-review hint pushes total lines beyond the body height (`crates/kuzushi-tui/src/renderer/views/onboarding/planning_picker.rs:15-23,47-59`). Option rows render only name/value/provenance (`planning_picker.rs:982-1049`), and the JSON preview is force-fit to one line (`planning_picker.rs:1138-1156`). Suggested fix: keep one stable master/detail layout at 120x36, reserve footer/prompt-hint height up front, present human labels plus `OptionSpec` descriptions, and wrap or scroll the canonical input preview. Reuse the existing selected-row detail and provenance patterns instead of exposing descriptor field names as the primary copy.

3. **[Display / data] A target selected with `target <path>` reaches Setup without repository facts.** Setup confirmed only `/private/tmp/kuzushi-opencode-review.HPIrp9`; it never disclosed the clean `dev` branch, revision `411eff73f0`, languages/build systems, nested scope, file count, or prior-artifact state, despite leaving most of the 120x36 body blank. Those facts are required to validate what will be scanned. Root cause: Setup renders only readiness rows and the selected row's short `detail` (`crates/kuzushi-tui/src/renderer/views/onboarding/setup.rs:5-23,26-48`), while the richer target-fact projection is private to the target picker (`crates/kuzushi-tui/src/renderer/views/onboarding/target_picker.rs:153-225`). Suggested fix: extract the existing target-fact labels into a shared view model and render the same generation-stamped facts beneath Setup's Target row for both picker and `target <path>` routes.

4. **[Data / display] A clean fresh target is labeled `workspace:stale snapshot` immediately and indefinitely.** The chip appeared on the first Setup frame and remained through Map-plan and Config screens. Cross-check: the opencode Git worktree stayed clean; the only new paths were Kuzushi-owned ignored `.kuzushi/v3/index.sqlite3*`, run-history, and project-model state. Root cause candidate: every successful watcher registration unconditionally sets the overflow flag (`crates/kuzushi-tui/src/app/runtime/workspace_watcher.rs:106-123`), and the overflow marker is projected as both `GitHeadChanged` and `.kuzushi/v3` (`workspace_watcher.rs:374-379`), which maps to the strongest `snapshot` stale chip. Suggested fix: distinguish registration reconciliation from a real channel overflow/source change, or clear the registration sentinel after the initial hydration. Reuse the existing state-fingerprint suppression path for Kuzushi-owned state rather than presenting an operator-actionable stale claim.

5. **[Display] The footer advertises `workbench` as the retired generic "command center."** This copy appeared on Capabilities and Config even though the product contract defines Workbench as the Map/Scan/Review/Prove/Fix workflow. Root cause: the label is injected into idle and default keybindings at `crates/kuzushi-tui/src/ui_view_models/keybindings.rs:188-203,228-237`. Suggested fix: label it `workflow` or the currently derived phase, mirroring the journey rail/chip vocabulary already used elsewhere.

6. **[Critical correctness / workflow] Choosing a credential method silently substitutes and persists a different model.** The operator explicitly selected and persisted `openai:gpt-5.5` with `xhigh`. Setup correctly blocked on missing credentials. Choosing the advertised OpenAI OAuth method reused the stored OAuth credential, marked Credentials ready, and silently changed the Model row and `~/.kuzushi/v3/config.toml` to `openai-codex:gpt-5.4`. No consent was requested for the model change. Root cause: the already-stored OAuth branch calls `select_oauth_model_for_provider` (`crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:637-649`); that resolves the provider's OAuth-default model and `select_auth_model_choice` overwrites both session state and global config (`picker_keys.rs:680-707`). The test `selecting_openai_oauth_auth_method_selects_oauth_model` explicitly locks in the unsafe substitution (`picker_keys.rs:1367-1380`). Suggested fix: credential selection must never mutate the selected model. If the selected model cannot use the chosen credential, preserve it and keep Setup blocked with an explicit compatibility error (for this case, “GPT-5.5 requires OPENAI_API_KEY”). Mirror the shared runtime no-silent-fallback hard-error policy; only an explicit Model action may change and persist the model.

7. **[Data / display] Config marks GPT-5.4 as selected while the active and persisted model is OAuth GPT-5.5.** After the explicit supported command `model openai-codex:gpt-5.5 xhigh`, Config's summary correctly displayed `model openai-oauth:gpt-5.5` and `reasoning xhigh`, and disk contained `model = "openai-codex:gpt-5.5"`. The MODELS table nevertheless put its `>` marker on row 3, `openai-oauth:gpt-5.4`. Root cause: an explicit model not present in `MODEL_CHOICES` cannot resolve by id, so `preferred_model_choice_index_for_state` falls through to the first ready OAuth-provider choice (`crates/kuzushi-tui/src/app/settings/preferred_model_choice_index_for_state.rs:3-14`). The Config projection then uses that catalog cursor as selection truth (`crates/kuzushi-tui/src/ui_view_models/config.rs:243-273`). Suggested fix: derive the selected marker from the canonical configured model. If it is outside the curated catalog, prepend an “explicit” row for that exact model or render no catalog row as selected; never mark a different model. Mirror the Config summary's direct use of `config.model`.

8. **[Data / workflow] Run Focus invents one extra task per dispatched tool and carries the duplicates across the plan.** Setup committed four actions: `context:build`, `entry-points:extract`, STRIDE, and PASTA. The first Run Focus header immediately claimed `0/5 done`. By the third run the task pane contained seven logical rows: five visible plus `2 not run`; it showed both `✓ Extract entry points` and `! Extract entry points`, and both a completed context label and a failed/truncated context label. Artifact cross-check shows exactly three independent run UUID tasks: context completed, entry points completed, STRIDE failed, and PASTA never started. Root cause: a new activity session seeds the four stable planning IDs (`crates/kuzushi-tui/src/app/tool_runner/run_tool/background.rs:433-449`), then the lifecycle projection inserts the current run's generated UUID as another row (`crates/kuzushi-tui/src/app/view_state/activity.rs:738-755`). Every continuation clones all prior rows (`activity.rs:385-404`), so the extra UUID rows accumulate. Suggested fix: bind the lifecycle task UUID to the current stable planning task before projection, or replace the seeded row when the first projected task arrives. Reuse the existing `bind_tool_task` alias mechanism so one planned invocation has one row and one status across its run UUID.

9. **[Data / workflow] The failed model call loses its actionable cause and duplicates the redacted fallback text.** The banner, `run.json`, `result.json`, and `failures.json` all report `Bridge operation failed; raw error details were suppressed.: Bridge operation failed; raw error details were suppressed.` The recovery advice says to fix the reported cause, but no cause, HTTP status, or meaningful class is reported. The semantic ledger does retain only the broad class `runtime_error`, exact model `openai-codex:gpt-5.5`, 517 ms latency, and unresolved spend. Root cause for the duplication: `StructuredOutputError` renders the complete source chain with `{:#}` and also exposes that same error as its `source()` (`crates/kuzushi-core/src/structured_output/structured_json_contract.rs:70-98`), so alternate-chain formatting prints the message twice. The wrapper is introduced for unresolved provider failures at `structured_json_contract.rs:272-284`. Suggested fix: make `Display` render only the immediate source display while preserving `source()` for chaining, then carry the bridge's safe structured `errorClass`/HTTP status into the operator failure handoff. Mirror the existing safe bridge classes in `scripts/langgraph-bridge/errors.mjs` instead of exposing raw provider text or collapsing everything to `bridge_internal`.

10. **[Data] `artifacts.json` declares `items.jsonl` twice under two path spellings.** The failed STRIDE manifest has nine rows but only eight distinct artifacts: `semantic run items` appears once as the absolute run path and again as relative `items.jsonl`. Root cause: canonical files are recorded with absolute paths (`crates/kuzushi-core/src/run_artifacts/artifact_manifest.rs:347-369`), while the lifecycle writer separately records the same canonical stream by its relative leaf (`crates/kuzushi-core/src/run_lifecycle/persistence/writer_open.rs:29-36`). Manifest upsert deduplicates only exact path strings (`artifact_manifest.rs:331-337`). Suggested fix: normalize every run-contained artifact to one canonical run-relative identity before upsert and rendering, using the existing contained-artifact normalization pattern in `run_lifecycle/application/terminal_persistence/artifacts.rs:91-108`.

11. **[Display] Run Focus truncates the most important labels while leaving most of the 120x36 frame empty.** On the failed Map screen, the task pane showed `Build a threat...`, `Extract entry points...`, `Build a lightweight...`, and a clipped legend, while roughly twenty rows below both panes were blank. The header also truncated the failure reason. Root cause: every width of 78 columns or more is forced side-by-side and the task pane is hard-capped at 40 columns (`crates/kuzushi-tui/src/ui_view_models/activity_layout.rs:25-46`); task labels are then fit into that narrow allocation after reserving nine columns for elapsed time (`crates/kuzushi-tui/src/ui_view_models/activity_dag_rows.rs:200-225`). Suggested fix: reuse the existing stacked layout when vertical space is abundant or when selected task labels cannot fit, sizing the task pane from measured content. Preserve side-by-side only when both panes have enough useful content to justify it.

12. **[Display / data] Activity timestamps silently show UTC as if it were local wall time.** At local `18:00:24 PDT`, Run Focus displayed `01:00:24` with no `UTC` suffix; the artifact epoch cross-check resolves to `2026-07-23 01:00:24 UTC`. Root cause: `wall_hms` intentionally takes epoch seconds modulo one UTC day and renders bare `HH:MM:SS` (`crates/kuzushi-tui/src/renderer/chrome/transcript/mod.rs:84-92`). Suggested fix: either append `Z`/`UTC` to the existing deterministic representation or render local time through a presentation-boundary clock; never present UTC as an unlabeled local-looking time.

13. **[Critical data / display] Run Focus drops every terminal lifecycle item and presents a terminal run as internally running.** Pressing the advertised `V` action worked on the first attempt, but the expanded screen said `Plan r1 · pending`, task `running`, tool call `running`, and model call `running`. Its health panel claimed durability only through sequence 11. On disk, the same `items.jsonl` is healthy through sequence 20: model call failed at 13, tool call failed at 14, task and plan failed at 18-19, and the terminal outcome is 20. Root cause: `apply_job_event` removes the job slot before it applies the terminal event and executes the returned persistence effect (`crates/kuzushi-tui/src/app/background_events/drain_background_events/runtime_event_drains.rs:74-91`). Terminal settlement then emits sequences 12-20 through the old generation's subscribers, but `JobHub::drain_one` treats every event for the removed slot as stale (`crates/kuzushi-tui/src/app/jobs/hub.rs:207-208,224-233`). Suggested fix: keep the generation live until observed-terminal settlement and subscriber delivery complete, then finish the slot. As a safety net, mirror the existing durable catch-up used for phase receipts (`runtime_event_drains.rs:311-335`) so Run Focus hydrates any terminal suffix from `items.jsonl` before presenting final state.

## Fixed & removed

None. `FEEDBACK.md` did not exist when this audit began, so there were no prior items to re-verify or remove.

---

## Verification update — 2026-07-24, refreshed 2026-07-27

The feedback implementation pass is complete for the TUI behavior covered by the automated contracts and live DevEx journeys below. This update records evidence rather than deleting the original dogfood reports.

### Live TUI evidence

- **J1 keyless first launch:** 11 machine checks passed, 0 failed, and all 3 human reviews passed. Target consent explains why selection is required; deterministic Setup now states `deterministic/runtime-free · no model or credentials`; the offline demo exposes real findings, target-relative locations, and signal-only proof state. Evidence: `scripts/devex/artifacts/20260724-163854/J1/`.
- **J7 findings triage and dismissal:** 2 machine checks passed, 0 failed, and all 4 human reviews passed. Finding detail now advertises decision, dismiss, and expiring suppression commands; durable decisions and suppression remain visibly distinct from gone findings. Evidence: `scripts/devex/artifacts/20260724-163854/J7/`.
- **J8 interrupt honesty:** 9 machine checks passed, 0 failed, and all 4 human reviews passed. Operator cancellation wins before terminal persistence, Jobs records `canceled`, Run Focus remains lifecycle-healthy, and no canceled task is presented as completed. Evidence: `scripts/devex/artifacts/20260724-174901/J8/`.
- **J12 Activity/viz auto-open:** 3 machine checks passed, 0 failed, and all 3 human reviews passed. Run Focus opens for live work, findings open the non-empty heatmap, and pages without backing artifacts render explicit empty guidance rather than fabricated data. Evidence: `scripts/devex/artifacts/20260724-154613/J12/`.
- **J18 failed Map recovery:** 11 machine checks passed, 0 failed, and all 3 human reviews passed. Prompt mode remains editable under an unresolved result, Navigate mode exposes the recovery actions, discard clears the checkpoint while retaining honest run evidence, and `next` opens a fresh Map plan. Evidence: `scripts/devex/artifacts/20260727-181144/J18/`.
- **Additional matrix:** J14, J16, and J20 passed their machine runs. J4 skips honestly without an Anthropic/OpenAI credential. J25, J26, J27, and J29 skip unless `KUZUSHI_DEVEX_TARGET` names a real monorepo; J29's root-first holistic state machine remains an explicit expected-fail product gap.

### Automated evidence

- `cargo fmt --all -- --check` passes.
- Focused cancellation, lifecycle settlement, key-remapping, planner-history, Setup, review-action, and canonical phase-snapshot tests pass.
- TUI integration suites pass: parity 113/113, snapshots 25/25, and stress 3/3.
- The TUI library suite passes with 2,460 passed, 0 failed, and 2 ignored, including the selected-proof and stale-proof provenance regressions.
- `cargo test --workspace --locked` passes across all crates, TUI integration suites, and doc tests.
- `pnpm verify:quick` passes its complete eight-step plan: Node tests, Rust formatting, workspace/all-target compilation, architecture, model safety, docs, CRAP risk, and Biome.
- `pnpm quality:architecture` passes 17 boundaries and 74 rules; `pnpm quality:crap-risk` passes for 365 changed code files.

---

## Audit 3 — FIRA reproduction / threat-model walkthrough (OAuth + gpt-5.3-codex-spark)

Date: 2026-07-30
Build: `0.24.0-alpha.8 · debug`, branch `feat/scan-comparison-honesty` @ 900d185389 (+ local uncommitted WIP)
Target: `~/academic/OMSCS/fira-reproduction` — 2292 files, Python, no build system detected, non-git
Model: `openai-oauth:gpt-5.3-codex-spark` (OpenAI OAuth, LangGraph backend), methodology `stride`
Session: interactive shell driven via tmux at 220x55.
Task: generate a DFD, entry points, and a STRIDE threat model, entirely through the TUI.

Outcome: **it worked.** `run threat-model:build` → prereq `context:build` approved → 2 runs / 92s →
`.kuzushi/threat-model.json` with 15 DFD nodes, 15 flows, 4 trust boundaries, 41 entry points,
5 assets, and 6 STRIDE threats (2 critical, 2 high, 2 medium). Evidence is file:line-anchored and the
provenance block honestly records "No source code execution, installs, or external network calls".
The items below are what got in the way.

### Feedback

14. **Auth picker claims credentials are missing when OAuth is already stored.** `auth` opened
    "CHOOSE AUTH METHOD" with the banner *"Provider openai needs credentials. Paste a key, sign in, or
    try the demo."* and defaulted the cursor to the API-key row. Selecting "OpenAI OAuth login"
    immediately returned `DONE onboarding · openai OAuth already stored; credentials hidden` — no
    browser flow, because nothing was needed. The `config` view confirms the state was knowable all
    along (`oauth openai=✓ stored`). The picker should lead with stored credential state and offer
    re-login as the secondary action, not present a first-run gate to an already-authenticated
    operator. Signifier↔state break: "needs credentials" was false when rendered.

15. **Esc-into-Navigate silently swallows a typed command — and fires real side effects.** After
    dismissing a notice with Esc, typing `model openai-codex:gpt-5.3-codex-spark` + Enter produced
    *nothing*: no prompt text, no error, no receipt, no model change. Esc had entered Navigate mode, so
    every character was consumed as a keybinding. Retyping the identical string without the preceding
    Esc worked on the first attempt. This is item 3's mode-flip papercut, still live, but now with an
    observable consequence: the swallowed keystrokes emitted
    `NOTICE keymap · operator keybindings reloaded` — navigate-mode bindings executed a real action
    from what the operator believed was command text. Typed printable input that lands in Navigate mode
    should either be rejected visibly or routed to the prompt; silently reinterpreting a command as
    hotkeys is the worst of the three options.

16. **Prereq card renders `recommendedapprove` with no separator.** In the PREREQUISITE PLAN card the
    label/value gap is lost on exactly one row:
    ```
      final tool threat-model:build
      missing via context:build
      recommendedapprove          <-- should be "recommended  approve"
      artifact   context snapshot
    ```
    Every other row pads correctly. Cosmetic, but it is on the one card that gates an approval decision.

17. **The derived phase chip oscillates Map → Scan → Map across a single tool run.** Before dispatch the
    rail read `Map 1/5` / `scope: … · Map`. While `threat-model:build` was in flight it read `Scan 2/5`
    / `scope: … · Scan`. On completion it reverted to `Map 1/5`. One run of one Map-phase tool should
    not transiently advance the journey spine — reality did not move to Scan and then back. Related to
    item 9's contradictory phase labels, but this is a *temporal* flip within one run rather than a
    disagreement between simultaneous indicators.

18. **`threats summary` reports `actors 0` for a model whose every threat names an actor.**
    `.kuzushi/threat-model.json` has no top-level `actors` array, yet all 6 threats carry an `actor`
    field (`adjacent_network`, etc.). Rendering a measured `0` states the model found no actors, when
    the truth is the concept is not modeled as a top-level collection. Either derive the distinct set
    from `threats[].actor` or render `—` / `not modeled` the way the ASSUMPTIONS block already does.
    (Same screen, same run: `assets 5`, `dfd nodes 15`, `data flows 15`, `trust boundaries 4` all
    match the artifact exactly — so `actors 0` reads as equally authoritative.)

19. **Cost is never metered for OAuth-backed models, so the budget rail is decorative.** Across a 92s
    run with a large synthesis call the header cycled `cost:$0.00 (no model calls)` →
    `cost:>=$0.00 (metering incomplete)`, Run Focus said `cost unavailable`, and the rail held
    `$0.00 spent · budget not enforced` throughout. For `openai-oauth:*` there is no per-call price to
    report, which is fine — but then the budget row should say so ("not metered for OAuth models")
    rather than implying a $0.00 measurement. A budget ceiling that can never be approached is worse
    than an absent one. (Item 2 flagged the repeated "cost unavailable" wording; this is the
    provider-specific root cause.)

20. **Grounding silently drops 43% of discovered attack surface.** Run Focus reported
    `grounding: 40 surfaces · 0 confirmed findings`. The context snapshot for the same target holds
    **70** surfaces (`attackSurfaceMap.surfaces`). The binding cap is the `maxElements` option,
    default **40** (`adapters/build_input.rs:19`), applied as
    `stratified_top_surfaces(map.surfaces, max_elements)` in
    `application/grounding.rs:186`, with `MAX_GROUNDING_ROWS_PER_FILE = 2` (`grounding.rs:191`) shaping
    the round-robin selection underneath it. Two problems compound: the cap is never disclosed, and
    `maxElements` does not appear in `options threat-model:build` at all — it is behind
    `show advanced`, so the default options view lists 7 knobs and hides the one that decides how much
    of the repository the model actually sees. The operator sees "40 surfaces" and reasonably reads it
    as *the* attack surface. This violates the repo's own standing
    rule: *"No silent caps: if a workflow bounds coverage (top-N, no-retry, sampling), log() what was
    dropped — silent truncation reads as 'covered everything' when it didn't."* Emit the denominator
    (`grounding: 40 of 70 surfaces · capped at 2 rows/file`) and carry it into the artifact's coverage
    block. Compare `provenance.notes`, which *does* honestly disclose its own limits — the grounding
    step should meet that bar.

21. **Minor: entry-point list clips its last group with no "+N more".** The ENTRY POINTS browser header
    reads `41 found · 4 kinds · 3 zones`; the visible groups are PROCESS EXECUTION 26, PUBLIC HTTP 12,
    SERVICE RUNTIME 3 (= 41), but only 2 of the 3 SERVICE RUNTIME rows fit before the panel border and
    nothing marks the truncation. The DFD page on the same screen does this correctly
    (`page 1/3 · +5 more`). The list does scroll with `j/k`, so this is a missing signifier rather than
    unreachable content — but the operator has no way to know a row is hidden.

### Verified fixed since Audit 1/2

Re-ran the surfaces that previous items called broken; these are genuinely better on this build:

- **Item 8, number-key tab footgun — fixed.** Pressing `4` on the threats view navigated to SUMMARY.
  It no longer drafts `model 4` into the prompt, so the accidental model-switch hazard is gone.
- **Item 8, UI/artifact threat-ID disagreement — fixed properly.** The TUI shows `T1…T6`, and the
  artifact now carries `displayId: "T1"` alongside `id: "T-MODEL-PICKLE-RCE"` and
  `stableId: "tm-e491895b7e81"`. TUI and JSON agree because the display identity is *in* the record
  rather than recomputed positionally. (Cross-referencing an export still requires the displayId→id
  hop; surfacing `id` in the detail pane would close it.)
- **Item 8, STRIDE rollup was "6 rows + 18 blank lines" — fixed.** The rollup now expands each category
  into its member threats with severity and title, and shows empty categories honestly as `0 issues`.
- **Item 7, DFD scene was display-only and lossy — largely fixed.** The scene now has a real selection
  model (`node 1/34`), a DETAIL pane (name/context/type/zone), per-zone pagination
  (`page 1/3 · +5 more`), `j/k follows selection`, `Enter DFD target`, and `g/G` ends. Node labels
  still truncate mid-word ("Mission/adjacent…", "AE forensics web…"), but the content is now reachable
  instead of unreachable.
- **Item 2, watchdog escalated during healthy long model calls — fixed.** The in-flight call rendered
  `◐ query in flight 1m04s · model call awaiting response` and the HEALTH pane stayed `Stream: healthy`
  for the full 92s. No false "NO PROGRESS SIGNAL" escalation. The lossy-progress disclosure
  (`healthy but lossy · 1 update(s) omitted` + `Disclosure · progress updates were coalesced at
  persistence · omitted=1`) is exactly the honesty this file has been asking for.
- **Run-focus origin restore works.** Completion returned to the exact pre-launch view
  (`options[threat-model:build]`) with one receipt — `run receipt · completed · 2 runs · 92s` — and did
  *not* force-open the DFD scene, which item 9 complained about. Opening `scene` explicitly worked.

### Re-run on the current release build (same day, 12:26)

The Audit 3 items above were collected on a `target/debug` binary built at 09:48 that reported its
revision as `unknown`. The npm-installed `kuzushi` on PATH was dead (its
`native/darwin-arm64/kuzushi` had been renamed to `kuzushi.npm-orig`, so the wrapper fell through every
resolution candidate and exited with "Could not find the Kuzushi native binary"). Rebuilt
`cargo build --release -p kuzushi-cli` (1m32s), re-pointed the alias
(`native/darwin-arm64/kuzushi` → repo `target/release/kuzushi`, `kuzushi.npm-orig` retained as
rollback), and re-ran the same task end to end on `kuzushi 0.24.0-alpha.8 (900d18538+dirty · release)`.

Items 14–21 were re-checked on the release build. **16 reproduces verbatim** (the prereq card rendered
`recommendedreuse` this time — the missing separator is not value-specific). **20 reproduces**
(`grounding: 40 surfaces` against 70 discovered). **19 got worse — see 22.** **17 did not reproduce**
on this path: launched from Workbench Map on a hydrated engagement, the phase chip held `Map 1/5` for
the whole run. The Audit 3 observation stands as recorded (fresh engagement, dispatched from the
`options` view), but the flip is path-dependent, not universal.

22. **A run with a 96,259-token model call is labelled `$0.00 (no model calls)`.** The release-build
    receipt read `completed · 1 run(s) · $0.00 (no model calls)`. The durable ledger for the same run
    (`.kuzushi/v3/runs/tool-1785439671340-9de9bfd27702/items.jsonl`, seq 12) records:
    ```json
    {"type":"model_call_finished","provider":"openai-codex",
     "model":"openai-codex:gpt-5.3-codex-spark","status":"completed","latency_ms":90617,
     "usage":{"inputTokens":56523,"outputTokens":39736},
     "cost":{"observedUsd":0.0,"completeness":"exact"}}
    ```
    Two separate defects:
    - `cost_label` (`crates/kuzushi-core/src/run_lifecycle/application/presentation/display/health.rs:93-104`)
      returns `"$0.00 (no model calls)"` whenever the report is complete and `observed_usd == 0.0`. It
      infers a **call count** from a **price**. A zero-priced call is not an absent call. The label
      should come from the model-call count in the ledger, which is right there.
    - `completeness: "exact"` asserts a measurement that never happened. The OAuth provider returns
      token usage but no price; classifying that as `Exact` (rather than `IncompleteObserved`, which
      the type already models and documents as "a provider call may have spent money but…") is what
      lets the false label render at all.

    Not a regression from the rebuild: every file on this path (`runtime_cost.rs` 2026-07-21,
    `health.rs` 2026-07-23, `langgraph_runtime/` 2026-07-28) predates **both** binaries, so the two
    builds ran identical cost code. Which makes it worse — the *same code* classified the *same
    provider and model* two different ways two hours apart: the 10:42 run recorded
    `completeness: "incomplete_observed"` (rendering the honest `>=$0.0000 (metering incomplete)`),
    the 12:29 run recorded `"exact"`. Cost completeness for an unmetered OAuth call is
    nondeterministic. This is the concrete mechanism behind item 19: budget enforcement cannot be
    trusted when a 96k-token call can settle as an exact $0.00.

23. **`seedMode=fresh` is inert — the previous model is loaded into the prompt anyway, and the run is
    stamped `fresh` while it happens.** The option is documented as *"fresh = build from repository
    evidence only, ignoring the previous model (document identity still carries forward)"*
    (`modules/threat_model_module.rs:190`). That promise is false in the default configuration.

    Traced end to end:
    - `default_source_artifacts(BuildFlavor::ThreatModel)` returns
      `["context", "threat-model"]` (`adapters/build_input.rs:314-319`), so `sources` includes the
      prior model unless the operator overrides it.
    - `load_parent_artifacts` (`application/source_bundle.rs:153-169`) dispatches
      `"threat-model" => load_prior_threat_model_source(input)` with **no `seedMode` check anywhere in
      the path**.
    - `load_prior_threat_model_source` (`source_bundle.rs:230-248`) reads the entire persisted
      document. `maxSourceBytes` is 200,000 and the file is 56,490 bytes, so nothing is trimmed.
    - `is_fresh()` has exactly one consumer: `stamp_build_seed_lineage`
      (`application/build_threat_model.rs:170-180`), where it decides the **provenance label** and
      whether to load `previous` for the lineage stamp. It never touches the prompt.

    Confirmed in the run's own artifacts. `input.json` records `"seedMode":"fresh"` alongside
    `"sources":["context","threat-model"]`; Run Focus reported `source:parent artifacts · 2 loaded`;
    and the persisted source-bundle record is unambiguous:
    ```json
    {"kind":"artifact","label":"threat-model","status":"loaded",
     "path":".../.kuzushi/threat-model.json","truncated":false}
    ```

    The output shows exactly what that produces. Across the two runs, **7 of 8 threat fields are
    byte-identical for all six threats** — the LLM-authored `id` slugs (`T-MODEL-PICKLE-RCE`,
    `T-CMD-EXEC-CONTROL`, …), `category`, `surface`, `asset`, `impact`, `likelihood`, and
    `relatedCwe`. Only `affectedFiles` changed, and it *shrank* (5 files → 3 on T1). `stableId` is
    hashed from `category|surface|asset` (`staged/evidence.rs:78-97`), so all six stableIds collide
    exactly. This is a paraphrase of a document the model was shown, not an independent re-derivation
    from repository evidence — which is precisely what `fresh` was supposed to prevent.

    (Separately, `finalize_document_identity` at `build_threat_model.rs:188-194` loads the previous
    model unconditionally to carry `T1..Tn` displayIds forward. That one is documented and intended —
    "document identity still carries forward" — so it is not a defect, but it does mean even the
    numbering is inherited.)

    Fix: either `fresh` must drop `threat-model` from `sources` before the bundle is built, or the
    descriptor must stop claiming the previous model is ignored. Today `seedMode` gates the *seed*
    channel while `sources` is a second, independent channel for the same document, and nothing
    reconciles them — so the one knob an operator would reach for to get an uncontaminated rebuild
    does nothing, and the artifact's own provenance says `seedMode: fresh` to confirm it worked.

    **Confirmed by controlled re-run (R3).** Dispatched
    `run threat-model:build {"seedMode":"fresh","sources":["context"]}` — same target, same cached
    70-surface context snapshot, same 40 grounded rows, same model — bypassing the broken knob by
    hand. Result: a **completely disjoint** threat set. R1∩R2 share **6 of 6** stableIds; R1∩R3 share
    **0 of 6**. R3 produced 8 threats (`T-01`…`T-08`) with no field overlap at all. Removing the prior
    model from `sources` is what `seedMode: fresh` was supposed to do, and doing it by hand changes
    the output completely — which is the proof that `seedMode` itself does nothing.

    Operator-visible side effect worth its own look: R3's eight new threats were numbered `T7`…`T14`
    by the displayId carry-forward, while the previous `T1`…`T6` are simply absent from the rebuilt
    document. A rebuild silently retired six threats and introduced eight more, with no diff, no
    retirement record, and no disclosure on the receipt.

24. **Entry points swung 41 → 17 on an unchanged target — root cause: the default pipeline persists a
    threat model that fails its own coverage invariant and reports it as a clean success.**

    `attackSurface.entryPoints` is **not** a deterministic projection of the attack-surface map. It is
    LLM output, partitioned by a prompt instruction in
    `application/grounding.rs:319`: *"Deterministic attack-surface map (ground truth: every row below
    must appear in attackSurface.entryPoints or in deprioritized with a reason)"*. Whether a given
    surface lands in `entryPoints` or in `deprioritized` is a model judgement call, re-made every run.

    The accounting shows what actually changed. The context snapshot holds **70** surfaces:

    The accounting across three controlled runs — same target, same cached 70-surface context
    snapshot, same 40 grounded rows, same model — with only the prior-model contamination varying:

    | run | prior model in prompt | entryPoints | deprioritized | accounted | coverage | invariant |
    |---|---|---|---|---|---|---|
    | R1 10:42 | yes (`seedMode: seeded`) | **41** | 29 | **70** (all discovered) | 40/40 | `true` · `none-needed` |
    | R2 12:29 | yes (labelled `fresh`, see 23) | **17** | 23 | **40** (grounded only) | 38/40 | `false` · `unresolved` |
    | R3 20:11 | **no** (`sources:["context"]`) | **6** | **0** | **6** (9% of discovered) | 21/40 | `false` · `unresolved` |

    **A hypothesis recorded here earlier — that item 23's seeding caused the entry-point collapse —
    is refuted.** The controlled run proves the opposite: removing the prior model made enumeration
    dramatically *worse*, not better. The prior threat model was doing most of the entry-point work.
    A genuinely cold build on this target yields **6 entry points out of 70 discovered surfaces**.

    **R3's six entry points are not entry points.** They carry `path: null`, `line: null`,
    `kind: null` and read as abstract buckets — `"AE forensics HTTP handlers"`,
    `"whitebox pixel_check_* os.system paths"`. Measured against the 33 distinct file paths in the
    discovered surface map: R1 represents **33/33**, R2 **27/33**, R3 **0/33**. So the cold run did not
    merely enumerate fewer surfaces; it collapsed 70 concrete file:line surfaces into 6 categories with
    no provenance at all, destroying the property that makes the deliverable useful (R1/R2 rows carry
    `source/FIRA_AE/AE/run_all.py:24` plus evidence arrays). `document_schema.rs:268` requires
    `path`/`line`/`method`/`route` on these rows; they are null and the document still validated and
    persisted as `completed`, because `require_complete_security_context_links` checks DFD reference
    integrity only, not evidence fields.

    R3 is the clearest failure of the ground-truth contract. `grounding.rs:319` instructs that every
    grounded row must appear in `entryPoints` **or** in `deprioritized` with a reason. R3 emitted 6
    entryPoints and an **empty** `deprioritized` array — so 34 of the 40 ground-truth rows the model
    was explicitly handed simply vanished, with no entry, no reason, and no record. The instruction is
    a prompt-level request with no post-validation that enforces it.

    Nothing enforces the invariant on the default path. All three runs used `pipeline: "single"` —
    the default (`adapters/build_input.rs:181-183` returns `"single"` when unspecified) — and
    `single_pipeline_gap_fill_method` (`application/build_threat_model.rs:421-427`) does nothing but
    **relabel** the failure:
    ```rust
    if coverage.invariant_satisfied() { "none-needed" } else { "unresolved" }
    ```
    The real remediation — the bounded STRIDE gap-fill pass over uncovered entry points
    (`staged/gap_fill.rs`, gated at `staged/pipeline.rs:120` and `staged/refine.rs:241`) — exists only
    in the *staged* pipeline. `single` computes the coverage report, discovers the invariant is
    violated, writes `"unresolved"` into the document, and completes successfully.

    And the failure never reaches the operator. Verified across every output surface of the failing
    run (`.kuzushi/v3/runs/tool-1785439671340-9de9bfd27702/`):
    - **Receipt:** `completed · 1 run(s)` — no warning, no degraded state.
    - **`report.md`:** zero occurrences of "coverage", "invariant", or "gap". The human-readable
      report omits the failure entirely.
    - **`result.json`:** `status: completed`; `invariantSatisfied: false` is present only nested inside
      the persisted document.
    - **Run Focus:** exactly one unstyled `tool-progress` line, `coverage: 38/40 entry points covered`
      (`build_threat_model.rs:405-419`) — no severity, no `⚠`, emitted into the same output stream
      that reported `1 update(s) omitted at source`.

    Suggested fix, in priority order: (a) a violated coverage invariant must not report `completed`
    unqualified — surface it on the receipt and in `report.md` as a partial/degraded outcome, since
    "21/40 entry points" is precisely the kind of bounded-coverage fact the repo's no-silent-caps rule
    already requires disclosing; (b) enforce the ground-truth contract in code rather than in the
    prompt — every grounded surface must land in `entryPoints` or `deprioritized`, and a run that
    drops 34 of 40 should fail validation, not persist; (c) give the `single` pipeline either a
    gap-fill pass or an explicit "gap fill unavailable on this pipeline" disclosure, rather than a
    silent relabel; (d) treat cold-start quality as the headline problem — 6 entry points from 70
    discovered surfaces is the *uncontaminated* result on this target, so a first-ever build against a
    new repository is the weakest case, exactly when the operator has nothing to compare it against.

    (The six identical STRIDE threats in R1/R2 are fully explained by item 23 — the prior model was in
    the prompt — and are *not* explained by this item. R3, with the prior model removed, produced a
    disjoint 8-threat set sharing 0 of 6 stableIds.)

25. **`provenance.sources` is LLM-authored free text, and it leaked a prompt fence delimiter into a
    persisted artifact.** The R3 build wrote:
    ```json
    "provenance": {
      "seedMode": "fresh", "pipeline": "single",
      "sources": ["UNTRUSTED_REPO_BEGIN", "attack-surface map",
                  "manual static traversal of referenced files"]
    }
    ```
    `UNTRUSTED_REPO_BEGIN` is the untrusted-content fence marker from the prompt, echoed by the model
    into the field that is supposed to record what the build consumed. Two consequences:
    - **`provenance.sources` is not evidence.** `seedMode` and `pipeline` are system-stamped by
      `stamp_seed_lineage`, but `sources` is model output, so it cannot be used to audit what actually
      entered a build. The trustworthy record is the source-bundle in `result.json`
      (`{"kind":"artifact","label":"threat-model","status":"loaded","truncated":false}`), which is
      system-written — that is what proved item 23. The two disagree freely: R1 claimed
      `repository-inventory`, R2 claimed `untrusted-source threat-model`, R3 claimed a delimiter.
      Either stamp `sources` from the actual bundle or rename the model-authored field so it cannot be
      mistaken for provenance.
    - **The model is attending to and reproducing the untrusted-content fence markers.** Benign here,
      but the fence is the prompt-injection boundary for repository content; a model that echoes the
      delimiter into structured output is worth a look before that boundary is relied on.
