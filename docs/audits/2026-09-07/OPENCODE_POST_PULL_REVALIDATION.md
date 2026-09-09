# OpenCode comparison after the Kuzushi pull

2026-09-07 · Kuzushi `586a6fda6d` · OpenCode `ecbc6ccac85b`

Historical committed-source snapshot. The [September 8 working-tree comparison](CURRENT_COMPARISON_2026-09-08.md) supersedes its current-status verdicts after interaction hardening.

**The original audit remains relevant. All six findings survive this pull at their original scope, but Kuzushi deserves more credit for readable layouts, recoverable failures, and truthful execution status.** The 21 incoming commits changed 66 files, including 16 TUI files. They repair adjacent problems; they do not complete the Map editor or inline question-and-answer experience.

This revalidation supersedes the present-tense comparison in the [original audit](~/vibe-code/Kuzushi/docs/audits/2026-09-07/OPENCODE_TUI_AND_SESSION_AUDIT.md). Its historical session receipts remain valid historical evidence. Its older-binary captures do not illustrate the new fixes.

## Which findings still apply

| Original finding | Verdict after pull | Rechecked behavior |
|---|---|---|
| F1 · High · Read the answer beside the diagram | **Still open** | Ask records the answer and announces `answer received. Next: logs`; Workbench still suppresses the embedded transcript. The Map card layout change adds no answer pane. |
| F2 · High · Lossless Map editing | **Still open; reproduced in the new build** | One comma-bearing document path became two sources. Left-arrow editing appended instead of inserting. Uppercase characters were also dropped in this terminal run; the field handler rejects modified character events. |
| F3 · Medium · Efficient configuration | **Still open** | The trial count still cycles from 2 through 50, with default 3; reaching 50 takes 47 activations. Scope still cycles through eligible leaves. |
| F4 · Medium · Readable batch findings | **Still open** | The batch row still puts counters and full location before the finding title, then truncates the whole string. The new entry-point row formatting belongs to a different renderer. |
| F5 · High locally · Executable provenance | **Still open on this machine** | A fresh debug build now exists, but the repository wrapper still selects the old `0.24.0-alpha.13` bundle and the global launcher still exits 127. Building the new source alone does not make those commands use it. |
| F6 · Low · Implementation language in controls | **Still open** | `descriptor input`, `canonical sast:scan input`, `detached dispatcher`, and routine routing/notification metadata remain in the cited surfaces. The new Setup disclosure is useful information and should be retained. |

The cited files were compared byte-for-byte between `a0eb23eb60`, current HEAD, and the working tree. None changed. I also reread the active control and rendering paths, rather than treating unchanged filenames alone as proof. [File comparison receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_FILE_CHECKS.json).

Current source receipts:

- F1: [answer completion](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/agent_session/ask_agent/agent_events.rs:64), [Workbench transcript suppression](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/chrome_layout.rs:91).
- F2: [edit round trip](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/map_run_config.rs:103), [delimiter parser](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/map_run_config.rs:257), [field key handling](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:297).
- F3: [trial control](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/batch_scan/config.rs:91), [scope cycle](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/onboarding/map_run_config/scope_policy.rs:31).
- F4/F6: [batch row and summary](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/campaign/batch_occurrence_lines.rs:67). In the same formatting example as the original audit, the title begins at column 102, beyond an 80-column view; this is a layout calculation, not an actual scan result.

## What is materially better

| Incoming fix | Before → now | What it resolves, and what remains |
|---|---|---|
| Map status-card sizing · #262 | A short actionable card could stretch to the bottom of the body → its height follows its rendered rows, with a title allowance and available-height cap. | Removes excessive blank card area, including an accepted context still awaiting a threat model. It leaves the ready Map gallery intact. This is not a repair to Ask output. |
| Entry-point identity · #254 | Hundreds of generically named entries could look identical → rows include their own location, preserving the filename/line when shortening long paths. | Improves selection without opening every row. The list can grow to 60 columns; insufficiently narrow rows retain the name. It does not repair batch finding rows. |
| Failed-result disposition · #263 | Typed failed results could omit the existing local discard control → blocked, failed, and canceled receipts include Discard. | Makes recovery more complete while retaining canonical run evidence. Successful and partial results do not acquire a new discard policy. |
| Threat-model patch failure · #264 | The UI could announce success and clear the pending patch before persistence succeeded → only a successful commit clears it; refusal retains it and offers retry/reject. | Fixes a trust-damaging false success and avoids requiring regeneration. Refusal also leaves an unrelated active run in flight. |
| Setup execution disclosure · #267 | The summary could truncate its instruction and omit the subsequent recommendation refresh → important summary segments wrap, and runnable Map plans disclose the expected background refresh. | Makes the committed work clearer at narrow widths. Empty/all-reused plans do not promise a refresh. Editing those plans remains limited by F2/F3. |

Source: [card geometry](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/phase_cockpit/composition.rs:305), [Map layout routing](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/ui_view_models/phase_cockpit/layout.rs:212), [entry row formatting](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/scene/entry_points/browser.rs:320), [typed-result policy](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/phase_results/typed_receipt.rs:103), [patch commit outcome](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/effects.rs:807), [Setup summary](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/renderer/views/onboarding/setup.rs:103).

There are also meaningful improvements beneath the TUI. A budget-stopped triage with unevaluated findings now reports Partial instead of Completed (#270), and CodeQL reports detected languages it could not analyze (#268). These changes improve what the operator can infer from the result. [Triage status](~/vibe-code/Kuzushi/crates/kuzushi-core/src/modules/triage/with_capacity.rs:73), [CodeQL output](~/vibe-code/Kuzushi/crates/kuzushi-core/src/scan/domain/scan_reports.rs:215).

The release change also restores three missing JavaScript bridge dependencies to the package inventory and adds an import-closure check (#251). That is a separate package defect from the missing local native executable in F5. The focused package-inventory suite passed all four tests on this working tree. [Package contract test](~/vibe-code/Kuzushi/scripts/npm-pack-inventory-contract.test.mjs:44).

## Comparison with OpenCode now

| Dimension | OpenCode reference | Updated Kuzushi | Assessment |
|---|---|---|---|
| Primary work area | A prompt on Home and a persistent scrollable conversation during a session | Durable phase pages and an embedded Map gallery; Ask's readable answer still lives in Logs | OpenCode remains the stronger reference for asking and reading without leaving the current context. |
| Editing and selection | Prompt history, attachment references, external editor; searchable command selection | Searchable grouped command palette already exists; dedicated Map/batch controls are more primitive | Reuse Kuzushi's stronger controls in the weak fields. Adding another palette would duplicate existing capability. |
| Information hierarchy | Optional sidebar, tool-detail controls, and generic output hidden by default | Better-sized Map card and distinguishable entry rows; batch titles still lose space to metadata | The gap narrowed in specific views. Consistency across result surfaces remains the next step. |
| Failure recovery | Session-bound commands, interruption, and persistent conversation | Newly complete failed-result discard and retained refused patches, alongside existing cancellation/auth-origin behavior | Credit the recovery fixes. End-to-end auth/cancellation reliability still needs a current-binary journey. |
| Domain evidence | Conversation and tool execution are the central organizing model | Accepted attempts, coverage gaps, finding identity, proof and patch lifecycle | Preserve Kuzushi's security workflow. A chat-only replacement would discard useful domain structure. |
| Verification confidence | Source pinned at `ecbc6ccac85b`; prior live capture used installed 1.18.18 | Current TUI source compiled and tested; its debug CLI was exercised at 120×36 and 80×24 | Current Kuzushi has direct terminal evidence. This is not a head-to-head latest-binary speed or pixel comparison. |

OpenCode receipts: [Home prompt width](~/clone-references/opencode/packages/tui/src/routes/home.tsx:34), [reachable/searchable commands](~/clone-references/opencode/packages/tui/src/component/command-palette.tsx:26), [external editor](~/clone-references/opencode/packages/tui/src/component/prompt/index.tsx:427), [output/sidebar controls](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:256), [scrollable conversation](~/clone-references/opencode/packages/tui/src/routes/session/index.tsx:1180). Kuzushi's existing [palette](~/vibe-code/Kuzushi/crates/kuzushi-tui/src/app/command_palette.rs:109) was also rechecked.

## Direct checks of the new Kuzushi executable

`cargo build -p kuzushi-cli --locked` succeeded. The explicit executable [target/debug/kuzushi](~/vibe-code/Kuzushi/target/debug/kuzushi) reports `0.24.0-alpha.14 (586a6fda6+dirty · debug)`. The dirty state reflects the preexisting backend edits; all TUI source matches HEAD. This is a build of the actual working tree, not a pristine-checkout benchmark.

| Live checkpoint | Result and evidence |
|---|---|
| Setup at 120×36 and 80×24 | The readiness summary, Start Map instruction, and expected background recommendation run survive. The new summary wraps at the narrow width. [120 columns](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/01-setup-120x36.txt), [80 columns](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/10-setup-80x24.txt). |
| Existing document named `docs/architecture, v2.md` | The intact draft saves as **2 sources**. This independently reproduces comma splitting without uppercase input. [Draft](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/05-lowercase-comma-path-draft.txt), [saved state](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/06-lowercase-comma-path-saved.txt). |
| Context: type `alpha`, Left, `b` | The field displays `alphab`, rather than `alphba`. The arrow did not move an editing cursor. [Result](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/07-left-arrow-ignored.txt). |
| Context: then type uppercase `X` | The field remains `alphab`. An earlier uppercase `A` in a filename was dropped too. This strengthens F2: its modifier guard also loses ordinary shifted input in this terminal setup. No claim is made about every terminal's encoding. [Result](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/08-uppercase-x-ignored.txt). |
| Unbuilt Map at 80×24 | The status card stops at its content instead of filling the body. No Map task was started. [Result](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/11-map-card-80x24.txt). |
| Recheck launch commands after building | Explicit debug binary: new revision. `node bin/kuzushi-rs.mjs --version`: old bundled revision. Global `kuzushi --version`: missing-binary error. The wrapper searches bundled native files before Cargo outputs. [Command receipts](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_LAUNCHERS.json), [candidate order](~/vibe-code/Kuzushi/bin/kuzushi-rs.mjs:44). |

These checks ran sequentially in one detached terminal against an explicit temporary target, with no model call or analysis run. The [keystroke record](~/clone-references/kuzushi-ux-audit-2026-09-07/post-pull-live/README.md) describes the fixtures and all captures. Ctrl+C opened an unsaved-plan exit confirmation while idle; confirming with `y` exited, and the audit terminal was then confirmed closed.

## Consequence for the session audit and priorities

The manual-session history is still useful for identifying repeated operator needs. It should not become a list of presumed present bugs. The input-event, OAuth-origin, activity-feed, DFD navigation, and Git-index watcher repairs cited in the original report are unchanged by this pull. The new work improves recovery and evidence inspection further. Historical assistant completion claims still need to be distinguished from tested operator outcomes.

The recommended order stays specific:

1. Use the explicit current debug executable for acceptance work, and correct the launcher selection separately so ordinary commands reach the intended build.
2. Complete readable Ask answers in the Map context.
3. Make paths/prose lossless to edit, and use numeric/searchable controls where choices are numerous.
4. Apply the improved entry-row hierarchy to batch findings without conflating occurrence with confidence or proof.
5. Verify the exact configuration → deliberate launch → result → follow-up sequence on that executable, including narrow terminals and recovery.

There is no evidence here for replacing the phase workflow or undertaking another broad architecture rewrite. The recent focused fixes are useful progress; completing the remaining interaction gaps is the stronger next investment.

## Verification and boundaries

- **74/74 phase-cockpit tests passed**, including the new Map card bounds and layout matrix. [Command/result](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_TUI_TESTS.json), [log](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_TUI_TESTS.log).
- **65/65 focused interaction/rendering tests passed** across Setup, entry-point browsing, typed receipts, threat-patch handling, Map card rendering, Map text parsing, batch controls, and transcript layout. [Command/result](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_INTERACTION_TESTS.json), [log](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_INTERACTION_TESTS.log).
- **4/4 package inventory tests passed**; the CLI build also passed, with seven TUI dead-code warnings. [Build receipt](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_CLI_BUILD.json), [verification summary](~/clone-references/kuzushi-ux-audit-2026-09-07/POST_PULL_VERIFICATION.json).

Passing tests are not a claim that F2 is solved: the existing parser test explicitly accepts comma delimiters, while the live path scenario demonstrates why that grammar is insufficient for document selection. The current live checks cover configuration, an empty Map, and idle exit. They do not cover completed analysis, generated diagram answers, expired-auth recovery, in-flight cancellation, batch findings, or export. Those findings remain source-backed where identified.

The OpenCode reference remained clean and unchanged. Kuzushi's preexisting core/runtime edits were preserved; all TUI source matched HEAD. No product source was edited. New outputs are the audit documents/evidence, build/test artifacts, and temporary input fixtures. No model request, scan, OAuth flow, or paid session was submitted. No native screenshot or controlled performance benchmark was taken.
