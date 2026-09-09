# OpenCode TUI comparison and Kuzushi session audit

2026-09-07 · Kuzushi source `a0eb23eb60adc770ef872b275ec9dfd38806f31b` · OpenCode source `ecbc6ccac85b3e8087b6445e584318419b9e2b34`

> Historical baseline. The [September 8 working-tree comparison](CURRENT_COMPARISON_2026-09-08.md) supersedes the current-status verdicts below. The [post-pull revalidation](OPENCODE_POST_PULL_REVALIDATION.md) records the intermediate committed-source state; original captures retain their older-binary provenance.

**Kuzushi’s central problem is the effort required to control and inspect work.** The operator repeatedly has to determine who owns the keyboard, whether a command opens configuration or starts work, whether an agent is progressing, and where its useful result went. OpenCode provides useful interaction patterns for these problems. Kuzushi should retain its evidence-oriented phase workflow and improve the controls and information hierarchy around it.

The strongest current gap is **diagram Q&A without a readable answer beside the diagram**. The strongest historical pattern is **a repair being declared complete before the operator’s actual interaction has been proved**. Several July/August failures now have concrete source fixes; this report does not relabel them as unfixed bugs.

## Scope and provenance

- Updated the existing clean `~/clone-references/opencode` checkout from `017a5977` to the current `origin/dev` via a fast-forward. The upstream is the [official anomalyco/opencode repository](https://github.com/anomalyco/opencode). Its package version is `1.18.29`; latest is pinned to the fetch during this audit, not promised indefinitely.
- Inspected current Kuzushi TUI source. Its TUI files had no uncommitted changes at the final check. Other core/runtime files already had active edits; they were not changed or treated as a frozen performance baseline.
- Indexed 162 top-level OpenAI coding-agent session files, 11 Claude files, and 8 OpenCode root sessions associated with the Kuzushi directory. Removed subagents, task notifications, injected goal continuations, scheduled-task prompts, and the current request. The resulting **candidate** digest contains 801 OpenAI coding-agent, 76 Claude, and 103 OpenCode turns; 146 sessions have retained turns. These include unrelated conversations, pasted audits, feature requests, and brief follow-ups. They are not 980 independent Kuzushi complaints.
- Used a topic search plus surrounding-turn inspection to select 37 historical receipts, then deep-read the relevant assistant/tool sequences. Two of the eight OpenCode root sessions concern unrelated work and were excluded from conclusions. This is a targeted qualitative investigation, not exhaustive coding of every transcript line. OpenAI coding-agent receipts span May–August, Claude August–September, OpenCode July–August. [Selected receipts](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md) retain original paths, line/part IDs, and UTC timestamps.
- Captured terminal content and ANSI at actual keystroke checkpoints, sequentially, without submitting a model request. **Runtime versions differ from source:** the bundled Kuzushi executable is `0.24.0-alpha.13 (69e1b4915+dirty)`; installed OpenCode is `1.18.18`. Source-backed findings below concern the pinned trees; these captures illustrate the installed binaries only. [Command provenance](~/clone-references/kuzushi-ux-audit-2026-09-07/PROVENANCE.txt).
- Native Terminal screenshots were denied by the computer-use tool. No pixel screenshots, physical contrast assessment, motion judgment, or full accessibility claim is made. No full current-source build, paid scan, fresh OAuth login, cancellation-in-flight, or export journey was run. No product source was edited.

## Current findings, ordered by operator impact

### F1 · High · Asking about a diagram still sends the answer elsewhere

**Scenario:** while viewing Map/DFD, ask a multi-paragraph question and try to read the answer while inspecting the diagram.

The new Ask implementation preserves the view and records the answer, but the completion path writes it to the log and announces `answer received. Next: logs`. Workbench explicitly hides the embedded transcript. The full readable text is in a separate Logs view. Other views can expose only a short fitted transcript strip. This is materially short of the August 26 request for questions and answers without a separate screen. [S2240](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:517)

Evidence: [agent_events.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/agent_session/ask_agent/agent_events.rs:64), [chrome_layout.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/chrome_layout.rs:19), [chrome_layout.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/chrome_layout.rs:91), [mod.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/help/mod.rs:183), [mod.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/chrome/transcript/mod.rs:68).

**Change:** a resizable, scrollable answer pane attached to the current Map view, with the selected model revision/component visible and a clear return to the diagram cursor. Reuse the existing Ask admission, context binding, cancellation, and transcript persistence. This requires a presentation completion, not another agent runtime.

**Acceptance:** a long answer remains readable beside the same selected node; follow-up questions keep that context; narrow terminals offer an explicit answer/diagram switch that restores cursor and draft. Source confidence: high; no current runtime reproduction.

### F2 · High · Map text editing cannot safely represent ordinary input

**Scenario:** attach `docs/Architecture, v2.md`, write prose containing commas, or move the cursor left to correct a long draft.

The dedicated editor maps both Design docs and Context through `parse_string_list`, which splits unconditionally on commas and newlines. There is no quoting/escaping grammar. The editor handles append, Backspace, Enter and Esc, swallowing other keys; it has no cursor movement or Delete handling here. A valid filename containing a comma becomes two paths, and one context item becomes several. The displayed value is also fitted to a single line. These are source-confirmed behavior limits, not hypothetical rendering failures.

Evidence: [map_run_config.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/map_run_config.rs:102), [map_run_config.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/map_run_config.rs:257), [picker_keys.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:297), [map_run_config.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/onboarding/map_run_config.rs:60).

**Change:** separate document selection from prose entry. Reuse the existing [file_picker.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/file_picker.rs:1) and [editor_state.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/editor_state.rs:1) where their contracts fit; preserve each path/item exactly and edit list entries individually. Keep descriptor validation at the shared boundary.

**Acceptance:** comma-bearing paths and prose round-trip unchanged; Left/Right/Home/End/Delete work; an invalid document is identified by name before starting. Source confidence: high.

### F3 · Medium · Configuration cost grows with the chosen value or repository size

**Scenario:** choose 50 batch trials from the default 3, or choose a specific leaf scope in a repository with dozens of scopes.

Batch trials advance one at a time and wrap from 50 to 2: setting 3 → 50 takes **47 activations** through this configurator. Scope advances through whole repository, each sorted eligible leaf, then all leaves. There is no searchable scope list in this path. These controls are acceptable for a two-item methodology choice but inefficient for numbers and many scopes.

Evidence: [config.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/batch_scan/config.rs:4), [config.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/batch_scan/config.rs:91), [controller.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/batch_scan/controller.rs:44), [scope_policy.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/map_run_config/scope_policy.rs:31).

**Change:** numeric entry with bounds; searchable scope selection showing names and selected count; a separate explicit launch action. Preserve worker clamping, budget disclosure, large-batch review and scope limits. Source confidence: high.

### F4 · Medium · Batch findings spend the row on counters before the finding

**Scenario:** compare scan outcomes in an 80-column terminal before entering Review.

The batch row puts repeated occurrence/completion/planned/failed counts first, then severity, full location, title and run IDs, and truncates the entire string. With `seen 2 / completed 3 · planned 3 · failed 0`, `HIGH`, and a 44-character Rust location, the title starts at zero-based column **102**. It disappears completely at 80 columns. This is a deterministic check of the source format, not a live scan finding. It repeats the historical pattern of available evidence being hard to read. [S1115](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:125) [S1941](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:429)

Evidence: [batch_occurrence_lines.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/campaign/batch_occurrence_lines.rs:86), [mod.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/shared/text/mod.rs:19).

**Change:** prioritize finding identity/title and severity; show occurrence compactly; put shared trial totals in the header and full location/run provenance in selected-row detail. Preserve completed-trial denominators and keep occurrence separate from confidence.

**Acceptance:** title, severity, occurrence and a path to full evidence remain available at 80×24; no finding disappears merely because its path is long. Source confidence: high.

### F5 · High locally · The launch path does not identify the source being evaluated

The globally installed `kuzushi --version` fails because its native binary is missing. The repository bundle runs, but reports an older dirty build. Consequently a user can restart “Kuzushi” and still fail to exercise the source fix discussed in a development session. The current capture still shows `CANONICAL INPUT`, while the current source and August 24 remediation explicitly removed it. This is direct evidence of local executable drift, not a claim that the latest published package is broken.

Evidence: [provenance](~/clone-references/kuzushi-ux-audit-2026-09-07/PROVENANCE.txt), [installed-binary Map plan](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/04-kuzushi-plan.txt), [OPTION_INPUT_SURFACES_AUDIT.md](~/vibe-code/Kuzushi/docs/audits/2026-08-24/OPTION_INPUT_SURFACES_AUDIT.md:17), [kuzushi-rs.mjs](~/vibe-code/Kuzushi/bin/kuzushi-rs.mjs:42).

**Change:** finish the development/install launcher path so the chosen command and artifact are unambiguous; record executable path, source revision, version and dirty state with every live acceptance run. Re-test the exact command the operator will run. Do this before deciding that a source fix failed again. Confidence: high for this machine; package-wide status unknown.

### F6 · Low · Ordinary controls still describe implementation details

The current threat-model editor says “Configure the descriptor input used by shell, run, and expanded scoped builds.” Batch UI exposes “canonical sast:scan input,” “detached dispatcher,” and an equivalence key in its main summary. Routine footers include `shell route` and `notify:unavailable · focus unknown`. These details consume scarce terminal space without helping the operator pick scope, understand a result, or edit a value.

Evidence: [map_run_config.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/onboarding/map_run_config.rs:9), [batch_scan_config_lines.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/campaign/batch_scan_config_lines.rs:10), [batch_scan_config_lines.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/campaign/batch_scan_config_lines.rs:88), [batch_occurrence_lines.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/campaign/batch_occurrence_lines.rs:67), [status_footer.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/status_footer.rs:124).

**Change:** keep scope, model, effort, cost, active work and next action prominent; move implementation receipts to details. Preserve actionable failures and provenance. Do not hide a real auth/budget/cancellation gate in the name of visual simplicity. Confidence: high for strings; visual prominence assessed from source and older terminal captures.

## What OpenCode does differently

| Dimension | OpenCode reference | Kuzushi and useful adaptation |
|---|---|---|
| First focal point | Home centers one prompt, bounded to 75 columns by default, with agent/model adjacent. [home.tsx](~/clone-references/opencode/packages/tui/src/routes/home.tsx:34) | Setup legitimately has more decisions. Keep its single Start Map action and explicit target consent, but make the selected decision more prominent than system metadata. |
| Commands | Palette is built from reachable commands, displays registered shortcuts, supports search and suggested actions. [command-palette.tsx](~/clone-references/opencode/packages/tui/src/component/command-palette.tsx:26) | Kuzushi already has a searchable grouped palette; it should not be rebuilt. Its entries combine shell commands, tools and modules. Improve contextual action selection and reuse the pattern in scope/batch configuration. [command_palette.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/command_palette.rs:109) |
| Input editing | Prompt supports history, attachment references, external editor and autocomplete, through one input surface. [index.tsx](~/clone-references/opencode/packages/tui/src/component/prompt/index.tsx:427), [index.tsx](~/clone-references/opencode/packages/tui/src/component/prompt/index.tsx:890) | Kuzushi’s specialized Map editor bypasses richer editing behavior. Standardize those field interactions. |
| Agent output | Session content is a persistent scrollable timeline; tool details and generic output have disclosure controls. [index.tsx](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:263), [index.tsx](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:1180) | Kuzushi now has typed run-lifecycle presentation, not merely timestamp strings. Finish the readable Ask result and per-task narrative using that shared data. [activity_feed_rows.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/activity_feed_rows.rs:76) |
| Long-running work | Interrupt is a named command bound to session state; the current implementation uses a two-step interrupt gesture. [index.tsx](~/clone-references/opencode/packages/tui/src/component/prompt/index.tsx:393) | Keep Kuzushi’s own cancel-without-exit and cleanup semantics. Borrow clear state/affordance ownership, not OpenCode’s exact key or guard policy. |
| Returning to work | Session selector searches top-level sessions with debounced queries and preserves current/pinned session entries. [dialog-session-list.tsx](~/clone-references/opencode/packages/tui/src/component/dialog-session-list.tsx:25) | Kuzushi needs engagement/attempt/finding truth rather than chat sessions alone. Make the current accepted result and explicit resumption action legible without discarding those distinctions. |
| Responsive hierarchy | Session sidebar is optional, appears automatically above 120 columns, and itself scrolls. [index.tsx](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:256), [sidebar.tsx](~/clone-references/opencode/packages/tui/src/routes/session/sidebar.tsx:33) | Keep Summary/DFD/Entry points/Components and their real-data empty states. Collapse secondary metadata before the useful finding or diagram content. F4 shows one current violation. |
| Trust model | OpenCode’s empty installed profile displayed a default model. | Kuzushi must retain explicit model selection, no silent fallback, proof states and approval gates. A calmer surface does not require adopting OpenCode’s defaults. |

This is a comparison of interaction mechanisms, not a controlled speed benchmark or a claim that OpenCode has no bugs. The comparator’s strong pattern is a stable primary work area plus consistent selectors and disclosures. Kuzushi’s strength is its durable security evidence and phase-specific views.

## What the manual sessions actually reveal

| Recurrent problem | Direct operator evidence | What can be said now |
|---|---|---|
| Input is slow, swallowed, or triggers an unintended action | July 13: “input is hella slow”; July 27 OpenCode: “why can't I type in the TUI”; August 26: “a lot of latency” and “It just straight up ran it.” [S1628](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:280) [S1892](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:323) [S2235](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:493) [S2239](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:511) | Multiple different mechanisms, not one bug. Current source batches input, rejects non-Press key events, and restricts result-card shortcuts to Navigate mode. These specific repairs are present; current loaded-workspace latency was not benchmarked. |
| Configuration, navigation and execution are hard to distinguish | July 2: phases/options unclear; July 14: step three not intuitive; August 26: Map should open generation configuration. [S1184](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:152) [S1695](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:298) [S2238](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:505) | The August 26 assistant first implemented durable-page navigation, then reversed it after correction, then fixed repeat/release acceptance. Intent and event ownership both needed repair. F2/F3 remain current friction. |
| Waiting lacks a useful explanation | June 30: wants more granular tasks and agent actions; July 1: no streamed actions; July 13: cannot tell if context is stuck. [S1099](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:83) [S1101](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:89) [S1120](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:131) [S1642](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:292) | Typed lifecycle rows, pause/follow and stalled-progress handling now exist. Do not propose another lifecycle rewrite or claim these are absent. Verify actual adapters produce useful events for long tasks. |
| Generated value is difficult to inspect | July 1 finding details; July 28–29 narrow DFD repeatedly invisible; August 1 component tree navigation. [S1115](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:125) [S1918](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:335) [S1937](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:417) [S1938](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:423) [S1962](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:435) | Current summary/component selection and DFD code has focused layout tests. Old blank-DFD reports are not current reproductions. F1/F4 are current examples of the same information-access problem. |
| Authentication interrupts the task instead of recovering it | June 12 frozen chooser; July 13 OAuth did nothing; August 20 scan failed; August 24 no route back after OAuth. [S1042](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:11) [S1621](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:256) [S2178](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:461) [S2218](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:481) | Source now carries auth origin and restores it after manual login. The August 20 failure was reported as missing credentials obscured by a generic bridge error; this audit did not submit a new auth/model call. |
| Prior work does not feel like a durable working environment | July 2 startup does not disclose previous scan; July 28 expects persisted DFD on reopen; August 26 explicitly requests repeated scans and questions in place. [S1193](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:158) [S1909](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:329) [S2240](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:517) | The current phase workflow, accepted attempts, threat-model configuration and scan batches are substantial progress. Judge the remaining work against that concrete brief, not against the retired four-pane design. |

Source checks for already-present repairs: [key_dispatch.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:17), [key_dispatch.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:96), [terminal_loop_event.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/runtime/terminal_loop_event.rs:8), [auth_login.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/settings/handle_model_command/auth_login.rs:119), [overview.rs](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/scene/diagram/dfd/overview.rs:318).

The OpenCode idle-CPU investigation is particularly instructive. Its initial user prompt suggested a missing poll debounce; the later assistant traced a feedback loop from read-only `git status` rewriting `.git/index`, through the watcher, back to hydration. Current `git_metadata.rs` sets `GIT_OPTIONAL_LOCKS=0` for the reads. **Do not add a timer to fix that already-addressed diagnosis.** [S1825](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:314) [git_metadata.rs](~/vibe-code/Kuzushi/crates/kuzushi-core/src/workspace/git_metadata.rs:141)

## The development loop is part of the problem

The clearest cross-tool example is August 18. An OpenCode session said the descriptor boundary was verified and the contract crate built. The subsequent Claude session checked the actual work and captured three descriptor compilation errors and two core compilation errors. The claimed refactor had not achieved its intended result. This is historical evidence of an execution/verification failure, not proof of a present broken descriptor crate.

Receipts: OpenCode database session `ses_feb07e735ffe48SwtfqBu071to`, assistant messages `msg_0150c79b9002T0ug1hmH3Apgt2` and `msg_0150cb8110027W9iK7OajCGRVu` at 2026-08-18 13:25 UTC; Claude [actual compiler output](~/.claude/projects/-Users-shayaunnejad-vibe-code-Kuzushi/757939e7-ae1e-4620-a2d0-1ae9a256a629.jsonl:84) and [core compiler output](~/.claude/projects/-Users-shayaunnejad-vibe-code-Kuzushi/757939e7-ae1e-4620-a2d0-1ae9a256a629.jsonl:96). [S2137](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:455)

A second example: the July 27 OpenCode session reported all major TUI/repository checks green at 20:46 UTC; at 22:55 the operator reported that typing no longer worked. The later diagnosis was a result card consuming Prompt-mode keys. The lesson is specific: broad green tests did not cover that interaction/state combination. It is not evidence that tests are useless.

A third example: August 26 required three successive interpretations/fixes—typing work, configuration versus navigation semantics, then release/repeat key acceptance. The session ended by telling the user to restart the old process. Today’s executable drift makes that last step a live concern. [S2235](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:493) [S2237](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:499) [S2238](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:505) [S2239](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:511)

A large redesign would repeat this risk. The user has also explicitly preferred the real current cockpit over replacement mockups. [S1773](~/clone-references/kuzushi-ux-audit-2026-09-07/SESSION_RECEIPTS.md:308)

## Recommended order and completion criteria

1. **Make the executable under test unambiguous.** Repair the local launcher/install mismatch; identify the current binary/revision in every acceptance receipt. Then recheck historical input/auth fixes on that binary.
2. **Complete the August 26 workflow in place.** F1 is the largest missing user-facing piece. Keep diagram context visible while the answer is read and followed up.
3. **Use proper field controls.** Address F2/F3 with lossless document selection, an actual text editor, numeric entry and searchable scopes. Preserve descriptor policy and explicit launch consent.
4. **Make results readable at ordinary widths.** Address F4; carry identity/title/severity/occurrence into 80×24 without hiding provenance or confusing recurrence with proof. Reduce the implementation copy in F6.
5. **Gate releases on the operator’s exact sequence.** Run sequential journeys on the same binary: existing target → `/map` configuration → change scope/methodology/docs → deliberate launch → inspect prior evidence while work runs → cancel safely → inspect/reopen result → ask about selected DFD node → read answer in place → scan batch → occurrence list → Review → export. Include fresh Press versus Repeat/Release, long pasted drafts, expired-auth recovery, restart, and 80×24/120×36/160×48. Record actual outcomes and explicitly name any model/credential-dependent portion not exercised.

Reuse the existing journey catalog and focused tests. A proposed responsiveness target is p95 ≤25 ms for a warm key-to-paint and ≤50 ms for a 40-character burst on a representative loaded workspace; these were goals in the August 26 session, **not fresh measurements from this audit**. Do not rerun the whole suite repeatedly without a new failure or change.

## Captured steps and limits

| Step | Captured action | Result |
|---|---|---|
| 1 | Bundled Kuzushi initial target picker | Target consent and navigation guidance visible; older build. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/01-kuzushi-initial.txt) |
| 2 | Escape to capability browsing | Grouped actions and target requirement visible. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/02-kuzushi-browse.txt) |
| 3 | Select an empty temporary target | Setup shows selected runtime-free plan and Start Map; no scan submitted. Not a full fresh-home J1 test. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/03-kuzushi-setup.txt) |
| 4 | Open Map plan | Editable plan visible, with old canonical-JSON presentation; demonstrates runtime/source drift. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/04-kuzushi-plan.txt) |
| 5 | OpenCode home, 120×36 | Prompt, model, command hint and provider connection hint visible. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/05-opencode-home.txt) |
| 6 | Open command palette | Suggested/contextual categories and key labels visible. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/06-opencode-commands.txt) |
| 7 | Search `model` | Palette narrows to Switch model; no model changed. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/07-opencode-search.txt) |
| 8 | Return and resize OpenCode to 80×24 | Primary prompt and hints remain visible. [Text](~/clone-references/kuzushi-ux-audit-2026-09-07/captures/08-opencode-80x24.txt) |

ANSI captures accompany every text file. Both audit tmux sessions were closed. The temporary target was empty, so its startup-created metadata is not scanner evidence. Live checks covered entry/configuration and command discovery, not completed scan/triage/proof/export work. No benchmark concludes that OpenCode is faster, and no current-source pixel comparison is claimed.

## Area verdicts

| Area | Verdict | Basis |
|---|---|---|
| Local executable readiness | FAIL | Global launch fails; bundled binary trails current source |
| Inline diagram conversation | PARTIAL | Safe contextual Ask exists; readable answer remains in Logs |
| Configuration controls | PARTIAL | Necessary options exist; input fidelity/cycling defects remain |
| Result readability | PARTIAL | Strong durable views; batch row sacrifices finding identity/title |
| Input/auth/progress repairs | PARTIAL verification | Repair code exists; current end-to-end runtime not tested here |
| Full visual/accessibility comparison | UNKNOWN | Native screenshots blocked; text/ANSI and source only |

The next investment should be these specific interaction completions and same-binary acceptance, rather than another architecture expansion or wholesale visual replacement.
