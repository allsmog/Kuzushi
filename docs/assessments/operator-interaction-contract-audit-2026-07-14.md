# Kuzushi Operator-Interaction Contract Audit — 2026-07-14

Status: remediation complete for the reproduced defects. Final aggregate gates
and the clean final-7 Prove/Fix replay are running; until those finish, this
report does not claim the completion gate.

## Executive summary

The audit reproduced twenty-six material operator-contract failures in the
compiled Rust/Ratatui shell. Frozen pre-fix and post-fix binaries prove them
through real Warp and detached-tmux journeys. Aggregate testing of the
concurrent adaptive Workbench work exposed zoom and compact-layout defects,
executor tracing found an accepted integer silently rewritten after descriptor
preparation, and later cancellation, Jobs, Prove/Fix, and key-remap replays
found eleven more attention, identity, and durable-lineage failures that focused
unit tests had missed.

The highest-impact failure was value loss across the guided Scan boundary. The
shell visibly accepted a descriptor-backed custom value, then asked it for a
cached task that was not in the execution plan. The operator saw acceptance,
but execution never received the value. The repaired flow derives questions
from the exact execution plan, validates Other values through the descriptor,
acknowledges the canonical name/value, and dispatched `maxFileBytes: 12345` in
the real `secret-scan:scan` run input.

A second lineage defect existed below the visible editor. The baseline binary
accepted `maxFileBytes: 1`, wrote that exact value to the canonical run input,
then silently scanned with a 1,024-byte lower clamp and reported a secret from
a file larger than the operator's accepted limit. Integer bounds now live in
`OptionSpec`, reject before a question advances, survive the trusted dynamic
module bridge, and are defensively rechecked by the executor instead of being
clamped or ignored.

The next cluster was attention and focus ownership. Phase-result cards
advertised action letters in Prompt mode even though dispatch accepted them
only in Navigate mode; a dynamic question simultaneously displayed COMPLETE
and WAITING INPUT; backgrounding that question allowed a one-line question
overlay to replace the Map composer, so text was stored and submitted while
invisible. The fixes make controls mode-aware, give a waiting question an
explicit nonterminal outcome, place the card beside the bottom input locus,
and render it only when Activity actually owns focus. This deliberately
preserves the Map-at-the-bottom view and its composer.

Warp exposed a terminal-specific paste defect that synthetic `KeyCode` tests
did not: Warp delivered CR-only multiline separators and the shared paste
normalizer deleted them. The normalizer now canonicalizes CRLF and CR to LF.
The real Warp regression displayed a two-line placeholder and the submitted
free-form answer was acknowledged without writing its text into durable run
artifacts.

The clean-zero fixture also found two durable-navigation defects. The journey
model advertised Report, but `next` ignored that destination and reopened the
Scan planner; Report Esc then returned to Fix rather than its exact Scan
origin. Both are fixed in the second frozen binary: literal `next` opens Report,
Esc and `q` restore Scan plus Prompt mode, and neither action creates a phase
attempt or another run.

The final partial-result and modal journeys found the remaining attention
conflicts. An unresolved partial Scan was surrounded by generic instructions
to rerun scanners; Activity accepted a command in Prompt mode while rendering
no composer at any tested width; and Jobs/Replay/Trace replacement polluted
navigation history so a later `back` reopened a departed deck. The repaired
projection gives unresolved result cards sole next-action ownership, reserves
the Activity composer only in Prompt mode, and makes contextual decks
history-transparent while preserving one exact workflow origin.

The final audit pass closed three cancellation contracts. Jobs said `running`
while Run Focus said `canceling`; queued row identifiers changed after another
row was removed; and a canceled engine was relabeled `failed` on the Scan
result card. Final-6 now keeps Jobs and Run Focus synchronized, assigns stable
queue selectors, persists canceled state through restart, and preserves the
terminal identity on the result card. A separate waiting-agent journey proved
that the exact compact identifier shown by Jobs now cancels the same live job
instead of returning `not running`.

Prove/Fix exposed two deeper identity failures. Verification accepted a model
fingerprint different from the requested finding, while several finding
writers minted secondary discovery IDs that had no canonical detector input
bundle. Strict normalization now rejects any present mismatched or invalid
fingerprint, and every ToolExecutionContext-backed writer uses the outer run
identity. Full Mode and Offense bypasses found by the final sweep were fixed at
the same boundary. An unresolved result's advertised Esc also did nothing, and
a remapped Prompt key produced contradictory footer/composer hints; final-7
uses the runtime keymap consistently and retains result-card first ownership.

That clean replay then found two final semantic gaps above the now-correct
lineage: choosing the advertised `Use proof set` recorded a selected attempt
without materializing proof on the finding, and a durably verified/restarted
patch still carried generic unresolved-candidate copy. Both fixes are in
progress and require a successor binary/replay before this report can close.

## Provenance and safety record

| Item | Recorded value |
|---|---|
| Repository | `/Users/operator/vibe-code/Kuzushi` |
| Branch | `codex/atlas-native-cockpit` |
| HEAD / upstream | `76974ccf5ce94f2cc099489ab4dcadfb1f5cb440` / same |
| Version | `0.24.0-alpha.8` |
| Initial worktree | 396 tracked changes and 89 untracked paths; none staged; all treated as user-owned |
| Current worktree | Concurrently changing during the audit; unrelated changes were neither discarded nor normalized |
| Baseline binary | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-baseline` |
| Baseline SHA-256 | `98439483511b797452cfeed34c376781b1c936ddc696e7ad12aec651bd99068a` |
| Baseline size/time | 157,172,472 bytes; 2026-07-14 12:19:09 -0700 |
| Frozen fixed binary | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final` |
| Fixed SHA-256 | `a77020bd0241dbda633cf82761887549bdeafe34d0919a4bc6082c357c5cbe60` |
| Fixed size/time | 156,767,704 bytes; 2026-07-14 13:44:06 -0700 |
| Frozen fixed binary 2 | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final2` |
| Fixed-2 SHA-256 | `d700bc0a669a6c2decd9181254788b53602f7c09c839094f0d891dc7bb16143d` |
| Fixed-2 size/time | 157,454,792 bytes; 2026-07-14 14:29:21 -0700 |
| Frozen fixed binary 3 | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final3` |
| Fixed-3 SHA-256 | `d90ab7906da95b616db7ce545eb1364f77b0e11dbaf48b4bd6811b64dcf9792c` |
| Fixed-3 size/time | 157,510,136 bytes; 2026-07-14 16:00:38 -0700 |
| Frozen fixed binary 4 | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final4` |
| Fixed-4 SHA-256 | `4c80920843553566e3f961b3ab0b45527a469b7dccf9e1759ec5726c61435b8e` |
| Fixed-4 size/time | 157,512,296 bytes; 2026-07-14 16:23:15 -0700 |
| Frozen fixed binary 5 | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final5` |
| Fixed-5 SHA-256 | `9ca0f5be8ee9965ccd51d2935c2c29a8066ad42b562623af51ec769e3be8e102` |
| Fixed-5 size/time | 157,512,280 bytes; 2026-07-14 16:29:06 -0700 |
| Frozen fixed binary 6 | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final6` |
| Fixed-6 SHA-256 | `52e1abd30fbe38222edaca98299466b8a10ed7b1fea3409b8d51be5efa9d7a04` |
| Fixed-6 size/time | 158,527,784 bytes; 2026-07-14 17:34:33 -0700 |
| Frozen fixed binary 7 | `/private/tmp/kuzushi-operator-contract-audit-019f621b/bin/kuzushi-fixed-final7` |
| Fixed-7 SHA-256 | `500cedf2b1b21d1bd59d0338ca23ebeed3a01ace09d9d04a4e3876ca805bf7c2` |
| Fixed-7 size/time | 158,528,696 bytes; 2026-07-14 17:46:21 -0700 |
| Interactive terminals | Dedicated Warp window for physical-key/paste proof; detached tmux for all later work |
| Alternate-screen capture | `alternate_on=1`; current screen captured with `tmux capture-pane -p -e`, never inferred from an empty normal-pane capture |
| Desktop-focus policy | After the operator requested no focus stealing, no AppleScript, click, raise, or Warp focus operation was used |

Each built binary was copied immediately to the isolated audit root and hashed
before a replay. The repository `target/debug/kuzushi` was rebuilt as a normal
implementation step but was never treated as immutable evidence. Fixture HOME,
TMPDIR, and XDG roots were isolated where a journey could otherwise consume
operator configuration.

## Expected operator journey

1. Select an explicit Target; Esc must enter an honestly targetless shell.
2. Review aggregate Setup without changing durable phase reality by navigation.
3. Commit Start Map and enter Run Focus only when the displayed dependencies
   are actually ready.
4. Resolve Map-to-Scan questions at the bottom input locus with the current
   prompt, progress, answer, and next action visible.
5. Select modules, satisfy prerequisites, and answer only options belonging to
   the exact execution plan.
6. Validate custom values through `OptionSpec`, then preserve the canonical
   value through planning, preparation, dispatch, run input, receipt, and
   restart projection where that value is durable.
7. Advance Map/Scan/Review/Prove/Fix only from canonical target/revision
   evidence. Page visits and focus changes never forge reality.
8. Preserve the exact workflow origin through Run Focus, backgrounding, Jobs,
   Replay, Trace, Activity, Report, and modal replacement.
9. On restart, reconstruct only from canonical run, phase-attempt, finding,
   proof, patch, and report artifacts.

## Journey matrix

`PASS` means the compiled fixed binary and canonical artifacts agreed. `PARTIAL`
means a bounded branch was proven but the full requested matrix was not.

| Journey | Fixture / terminal | Before | After | Evidence |
|---|---|---:|---:|---|
| Explicit Target → Setup → Start Map → Run Focus → exact Setup return | Fresh J14 target, 60×20 tmux | PASS | PASS | `scripts/devex/artifacts/20260714-131853/J14` — 16 pass, 0 fail |
| Unresolved successful Map result; Prompt/Navigate ownership | F02/F07, 120×36 tmux | FAIL | PASS | Baseline `F02/01-unresolved-map-result.txt`; fixed `F07-fixed/01-prompt-u.txt`, `02-navigate-u-selected.txt` |
| Accepted current Map → guided Scan | F03, 120×36 tmux | FAIL | PASS | `captures/F03/*`; fixed `captures/F03-current-fixed/01-route.txt` through `12-terminal.txt` |
| Guided module Other is additive and requires explicit Continue | F03 | FAIL | PASS | Fixed `06-additive-ack.txt` retains secret-scan + semgrep and adds CodeQL |
| Context-built task skips irrelevant questions | F06/F03 | FAIL | PASS | Fixed first option is `secret-scan:scan target`; cached context options are absent |
| Descriptor Other invalid → correction → canonical dispatch | F03 | FAIL | PASS | `09-invalid-retained.txt`, `10-accepted-12345.txt`, canonical run input |
| Descriptor integer below executor minimum | F13, baseline/final-3 headless + focused TUI/core | FAIL | PASS | Final-3 exits 1 with `must be at least 1024`; its durable run is honestly `failed` and no scan result is produced |
| Failed Scan result remains unresolved and actionable | F08, 120×36 tmux | PASS | PASS | `captures/F08/01-failed-result-esc.txt` |
| Partial Scan result → explicit acknowledgement → restart | F14, 80×24 detached tmux | FAIL for conflicting global guidance | PASS | [Final-5 record](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F14-partial-final5/AUDIT-RECORD.md): card/NEXT align, conflicting hints absent, one `acknowledged_partial:true` disposition, restart hash stable |
| Imported finding Review → Prove → Fix inspection | F09, 120×36 detached tmux | — | PARTIAL | Imported identity/proof absence/reality preserved; no model-backed verify or patch was authorized |
| Background dynamic question → Map → Activity → exact answer | F11, Warp + tmux | FAIL | PASS | `Warp-F11-fixed/01` through `03` |
| Dynamic multiline Other through actual Warp paste | F11, physical Cmd+V | FAIL | PASS | `Warp-F11-fixed/04-warp-multiline-paste-placeholder.*`, `05-freeform-sanitized-ack.*` |
| Restart after durable guided run | F12, detached tmux | — | PASS | `captures/F12-fixed-restart.txt` |
| Clean zero-finding current-revision Scan → Report → exact return | F10, headless + 120×36 detached tmux | FAIL | PASS | Fixed-2 `next` opens Report; Esc and `q` restore exact Scan/Prompt origin without durable mutation |
| Review → Activity Prompt → Jobs → Esc → back | F15, 40×12/100×30/120×36 detached tmux | FAIL | PASS | Final-4 Activity draft is visible; Jobs Esc restores Activity/Prompt; back restores Review |
| Replay → Trace → Jobs replacement → exact origin | F15, 100×30 detached tmux | FAIL on later history traversal | PASS | Final-4 Esc restores exact Review/Prompt; phase/run artifact hashes unchanged |
| Triage decision and suppression remain visible | J7, detached tmux | — | PASS with harness caveat | `scripts/devex/artifacts/20260714-135131/J7`; harness expected stale text but captures show DIS state |
| Stale Map refuses silent Scan advance | F04, 80×24 detached tmux | — | PASS | `captures/F04-stale-map-final5`; stale revision disclosed, no Continue-to-Scan action, restart hashes unchanged |
| Missing-context card full keyboard/editor matrix | F05, 80×24 detached tmux | FAIL for 512-character cursor locus | PASS | [Final-6 record](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F05-context-card-final6/AUDIT-RECORD.md); cursor/tail visible, no submit or artifact mutation |
| Live cancel → Jobs → stable queued work → canceled result | F16, 80×24 detached tmux | FAIL for Jobs state, selector identity, and result label | PASS | [Final-6 record](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/AUDIT-RECORD.md); scoped cancellation, process cleanup, stable `queued-2`, one drain, durable canceled identity |
| Waiting agent canceled by the exact Jobs display ID | F20, 120×36 detached tmux | FAIL | PASS | [Final-6 record](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F20-jobs-agent-display-id-final6/AUDIT-RECORD.md); `WAITING INPUT → canceling → canceled`, restart agrees |
| Remapped result-card Prompt key and advertised hints | F21, 80×24 detached tmux | FAIL for hardcoded composer hint | PASS | [Final-7 record](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F21-phase-result-remap-final7/AUDIT-RECORD.md); footer/composer both say `x prompt`, Esc/a owned, x enters Prompt |
| Native finding → Prove → Fix → apply → reverify → restart | Fresh deterministic target, 120×36 detached tmux | FAIL for verification and detector identity | PASS for required lineage/lifecycle; two new semantic failures | [Final-7 record](/private/tmp/kuzushi-operator-contract-audit-019f621b/prove-fix-final7/AUDIT-RECORD.md): all required assertions pass without synthetic binding; proof-selection reality and verified-card copy are now being remediated |
| Plain/non-TTY target truth | J16 | — | PASS | `scripts/devex/artifacts/20260714-134942/J16` — 5 pass, 0 fail |
| Compact Prove normal → zoom → Map bottom composer → restart ResultReady | Final-3 demo plus final-5 Map repeat, 40×12 detached tmux | FAIL for compact clipping | PASS | Final-3 `01` through `04`; final-5 bottom row is `◇ MAP › map-bottom-final5`; all captures `alternate_on=1` |

## Fixture matrix

| ID | Required state | Exact state exercised | Result |
|---|---|---|---|
| F01 | No `.kuzushi` | J14 isolated `fixture-target`; no state before launch | PASS for Target/Setup/Map origin |
| F02 | Map artifacts, no selected attempt | Completed Map attempt `phase-5a2910898fd949afb1c4603ae1560a35`, unresolved | PASS after control-hint fix |
| F03 | Selected current Map | J14 target with accepted current Map/context; guided three-engine run | PASS; terminal Scan failed honestly because CodeQL exited 2 |
| F04 | Stale Map artifacts | Map recorded at `12ccf739…`; target advanced to `437d23cc…`; two detached restarts | PASS; exact stale prompt, no Scan advance, literal BackTab/Other/Ctrl+C matrix, ledger/run hashes unchanged |
| F05 | Context missing | Fresh target `cbe2103a…`; no context snapshot, phase ledger, or run directory | PASS; prerequisite keyboard/editor path plus literal 512-character bracketed paste, visible tail/cursor, no submission/mutation |
| F06 | Context built | F03 context snapshot present; cached context task omitted from execution questions | PASS |
| F07 | Unresolved successful result | Completed current Map attempt with no disposition | PASS |
| F08 | Partial, failed, canceled | Failed Scan exact; real partial acknowledgement/restart exact; controlled long Semgrep cancellation with one queued successor | PASS; Jobs/Run Focus agree while canceling, terminal artifacts and restart say canceled, successor drains exactly once |
| F09 | Imported findings | HAR import run `run-1784062999-3ca56d8f5472`, one F-0001 imported finding, no modern attempt ledger | PASS for durable imported identity/reality; execution path partial |
| F10 | Clean zero-finding Scan | Git `c6b7a92c41b29cad95211180fec5cd02070cf3d4`; run `scan-1784063371-0523366f2bc5`; completed; 0 findings | PASS after destination/origin fixes |
| F11 | Background work waiting for input | Generation-scoped dynamic question in run `agent-1784061880-b80b290794cd` plus later size-matrix run | PASS after fixes |
| F12 | Reopened process | Durable F03/F10 artifacts reloaded in a new shell | PASS for durable state; a process-local waiting question is not resumable and remains a documented risk |
| F13 | Integer lineage boundary | Fresh 58-byte secret fixture; baseline successful run with `maxFileBytes=1`; final-3 durable failed/refused run | PASS after descriptor/executor fix; exact record in `captures/F13-range-lineage/AUDIT-RECORD.md` |
| F14 | Unresolved partial result | Current-revision Map skip plus unresolved typed `scan/partial` receipt; no in-memory injection | PASS after guidance fixes; explicit acknowledgement and restart proven in detached tmux |
| F15 | Contextual origin and Activity input | Hydrated Review fixture with canonical run `scan-1784070138-0a32bfe8df97`; phase/run hashes inventoried before and after | PASS after composer/history fixes; no durable mutation |
| F16 | Stable pending-work identity | Live Semgrep plus `queued-1` secret and `queued-2` license; first row removed before a delayed retry | PASS; license remains `queued-2`, stale `queued-1` cannot hit it, then drains once after the live run terminates |
| F17 | Background work waiting for input | Agent run `agent-1784075953-05e2b2cfa0f2`, full ID compacted to `b2cfa0f2` in Jobs | PASS; the literal displayed ID targets the same generation and persists canceled through restart |
| F18 | Native detector finding and patch lifecycle | Fresh git target `e9fe4dfa…`, real Secret Scan, deterministic triage/verify/patch bridges, reviewed source mutation | PASS for native detector binding, strict verification, approval/apply/reverify, and restart; follow-up defects F-25/F-26 remain in remediation |

Full F10 fixture commands, hashes, and canonical-artifact inventory are in
[`AUDIT-RECORD.md`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/AUDIT-RECORD.md).

## Question-card transition table

| State | Entry condition | Focus / actions / advertised shortcut | Resulting state | Durable mutation | Navigation, Esc, invalid, restart |
|---|---|---|---|---|---|
| Guided Map route | `scan` with accepted/prior/no Map | Recommended route; arrows, `j/k`, numbers, Enter; Tab only because Other exists | Module selection, rerun Map, or retained route error | None | Space is now a no-op; Esc dismisses with draft preserved; page visit does not mutate reality |
| Guided module selection | Runnable phase tasks loaded | Continue row focused; Space/Enter toggle module; `c` Continue; Tab Other | Configure exact runnable tasks | None until launch | Other lookup failure stays open; valid match is additive, acknowledged, and does not advance automatically |
| Guided Context prerequisite | Selected Map task requires missing context | Recommended Build Context; Enter or explicit alternative | Context build then same generation resumes | Context artifacts only after successful build | Cached context removes this stage; Esc preserves selection |
| Descriptor option choice | Exact execution-plan task has visible `OptionSpec` | Prepared/default value; Enter keep, arrows/numbers, Tab Other, `a` remaining defaults | Next descriptor option or Run Focus | Scoped planning override only | Invalid type or range keeps the exact draft plus a precise error; accepted value names canonical option; cached/skipped tasks cannot create questions |
| Guided Other editor | Supported Other explicitly opened | Visible `EditorState` cursor; printable/Shift, paste, arrows, Backspace, Ctrl+W/Alt+Backspace, Enter, Esc | Validated parent state or same editor with error | No raw draft event/log | Esc returns to prior selection; multiline paste stays one explicit placeholder/submission; long drafts keep the cursor-centered tail visible |
| Phase result — Prompt | Unresolved completed/partial/failed attempt while composer owns input | Composer; `F2 Navigate` (or resolved override) is the only result control advertised; global NEXT repeats the card recommendation | Navigate mode | None | Literal result letters remain composer input; draft-blocked and unbound states are disclosed; generic phase-run hints are suppressed |
| Phase result — Navigate | Same card with Navigate active | Only allowed result actions (`u/n/o/f/r/d` by outcome) plus the runtime-keymap Prompt binding; result card retains sole next-action ownership | Select/continue, Replay, rerun, discard, or Prompt mode | Typed attempt disposition only for resolving actions | Default Esc or remapped `x` enters Prompt without resolving; an unbound/remapped Esc is a scoped no-op; footer and composer disclose the same binding; ordinary printable input cannot leak |
| Dynamic choice | Live worker emits matching run/request/generation | Bottom Activity card; Enter, Esc, `b`, arrows, `j/k`, numbers, Tab only with Other | Submitting, backgrounded, canceled, or Other | No answer text persisted by UI | Card owns keys first; background never steals focus; stale IDs are refused by worker boundary |
| Dynamic Other | Other supported and opened | Visible editor; Enter submit, Esc return, word/cursor editing; no false selection hints | Matching generation resumes | Sanitized acknowledgement only | CR/CRLF paste is lossless; free-form text absent from durable events/run input |
| Background waiting | Operator presses `b` | Workflow origin/composer owns keys; attention footer advertises waiting work | Activity/Jobs can reopen same request or cancel it by the displayed Jobs ID | None until answer/cancel | Question never renders over Map composer; accepted answer restores origin with receipt; cancellation persists terminal identity and restart no longer claims liveness |
| Activity — Navigate | Run Focus or manual Activity inspection owns pane controls | Full-frame Run Focus controls; Esc advertises Prompt | Activity Prompt | None | No generic composer row while navigation owns input |
| Activity — Prompt | Esc from Activity Navigate | Visible bottom composer; printable/Shift/paste and commands | Command target or F2 back to Navigate | Only the submitted command's normal effects | Draft is visible at 40×12, 100×30, and 120×36; Jobs Esc restores Activity/Prompt exactly |
| Contextual deck replacement | Jobs/Replay/Trace/Scene opens over a workflow origin | Deck owns its controls; replacements retain one origin; Esc closes | Exact original view and input mode | None for navigation alone | Decks are history-transparent; a later `back` continues beneath the restored origin instead of reopening a departed deck |
| Clean Scan Report destination | Accepted current Scan has zero candidates | `next` advertised as Report | Report, then Esc/`q` restores exact Scan/Prompt origin | None | PASS in fixed-2; restart preserves the same run/reality |

## Keystroke and input matrix

| Input | Guided cards | Dynamic card | Result card / views | Verdict / evidence |
|---|---|---|---|---|
| Enter | Choice/toggle/submit | Choice/submit | Navigate action/open | PASS |
| Esc | Dismiss/return, draft preserved | Return from Other or cancel | Replay/Report restore origin; default result-card Esc enters Prompt; remapped Esc is an honest no-op | PASS |
| Tab | Opens Other only when supported | Opens Other only when supported | Pane/completion by mode | PASS |
| Literal BackTab `ESC[Z` | No corruption; mode binding honored | Physical Warp path exercised | Mode binding exercised | PASS |
| Up/Down/Left/Right | Cursor/choice/editor movement | Option/question/editor movement | Pane/scroll | PASS |
| `j` / `k` | Choice navigation | Choice navigation | View navigation | PASS |
| Number shortcuts | Direct visible choice | Direct 1–3 answer | Phase 1–5 page navigation | PASS for displayed ranges |
| Space | Module rows only | Pause remains Run Focus action, not question selection | No hidden route action | PASS after fix |
| `c` | Explicit module Continue | — | — | PASS |
| `a` | Accept remaining prepared defaults | — | — | PASS |
| `b` | — | Background without cancellation | Run Focus background | PASS |
| `o` / `u` | — | — | Open evidence / select Map | PASS in detached tmux |
| `r` / `d` / `f` | — | — | Result rerun/dismiss and Prove/Fix actions exercised across deterministic journeys | PASS for applicable cards; destructive apply still requires explicit approval |
| Ctrl+C | Releases to shared two-stage cancellation | Releases to shared cancellation | Long-running cancel, canceling cleanup, durable canceled result, and two-stage exit | PASS in final-6 detached terminal |
| Lowercase | Visible editor draft | Visible editor draft | Composer | PASS |
| Shift uppercase / punctuation | Accepted by `EditorState` | Physical Warp `customA!` | Composer | PASS |
| Backspace | Cursor-aware | Cursor-aware | Composer | PASS |
| Ctrl+W / Alt+Backspace | Deletes a word in Other | Deletes only while Other owns input | Shared composer unaffected | PASS after fix |
| Normal paste | Same focused editor | Same focused editor | Composer | PASS |
| Multiline paste | Lossless placeholder; no auto-submit | Physical Warp CR-only paste retained two lines | Composer contract unchanged | PASS after fix |
| Empty input | Precise “enter a value...” error | Existing choice remains selected | Composer no-op | PASS in focused tests; partial live |
| Whitespace | Descriptor coercion/lookup trims only at validation boundary | Free-form remains an answer category | Composer preserves draft | PARTIAL; no exhaustive live leading/trailing matrix |
| Long input | 512-character draft keeps tail and cursor visible without submit | Same editor implementation | Same shared prompt viewport | PASS for 512 ASCII and focused double-width Unicode; unbounded/O(n) remains a performance risk |
| Unicode | Guided paste/editor accepted Unicode | Editor path uses Rust chars | Composer | PASS for editor path; not all descriptors permit arbitrary Unicode |

## Value-lineage report

### Descriptor Other: `secret-scan:scan.maxFileBytes`

| Boundary | Proof |
|---|---|
| Terminal event → focused editor | Tab opened Other on the `max file bytes` option; `12x` remained visible with cursor |
| Draft → validation | Enter produced `must be an integer, got "12x"` without advancing; `1` now remains visible with `must be at least 1024` |
| Correction → coercion | Backspace/correction to `12345` produced integer JSON value |
| Descriptor boundary | `planning_option_spec` resolved canonical `OptionSpec.name == "maxFileBytes"`; `OptionSpec.minimum/maximum` enforce the inclusive 1,024–67,108,864 range during canonical preparation |
| Scoped override | `set_planning_option_override` stored the value for `secret-scan:scan`, not globally or by label |
| Immediate acknowledgement | Next card showed `Accepted max file bytes = 12345` |
| Prepared/dispatched input | `scripts/devex/artifacts/20260714-131853/J14/fixture-target/.kuzushi/v3/runs/tool-1784060546-89473442167d/input.json` contains `"maxFileBytes": 12345`; the executor-level regression scans a 2 KiB fixture only with that accepted limit, not with 1,024 |
| Other executors/defaults | Semgrep and CodeQL inputs contain only their own canonical defaults; neither overwrote the secret-scan value |
| Receipt/restart | The three engine run refs and failed aggregate receipt survived restart; the custom value remains in the canonical secret-scan run input |

Baseline bound-failure proof is
[`01-baseline-accepts-1.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F13-range-lineage/01-baseline-accepts-1.txt), with canonical input
`/private/tmp/kuzushi-operator-contract-audit-019f621b/fixtures/F13-range-lineage/target/.kuzushi/v3/runs/run-1784069483-181402bcb422/input.json`.

Regression tests:
`other_option_is_visible_and_reaches_descriptor_prepared_input`,
`out_of_range_descriptor_other_remains_visible_for_correction`,
`valid_secret_scan_other_reaches_canonical_prepared_input`,
`secret_scan_integer_ranges_reject_silent_rewrites`, and
`custom_file_limit_changes_the_executed_scan`.

### Module Other: `CodeQL`

The editor resolves the label/tool name against current phase rows, constructs
an additive proposed selection, validates availability, and then writes the
canonical `PlanningTaskId`. Fixed evidence showed secret-scan and semgrep still
selected, CodeQL newly selected, acknowledgement `Added CodeQL security scan ·
3 selected`, and no automatic advance. Later run input identifies canonical
`codeql:scan`. Arbitrary unmatched text stays in the editor with a precise
lookup error.

Regression tests:
`module_other_adds_without_erasing_existing_selections` and
`unavailable_module_other_stays_open_without_partial_selection`.

### Cached context option: `sampleLimit = 37`

Baseline lineage stopped after visual acceptance. The UI asked an option for a
cached context task, displayed `Accepted sample limit = 37`, and later launched
only CodeQL; no dispatched input contained 37. The durable fix does not attempt
to persist a meaningless override. It builds option targets from
`build_execution_plan(...)`, so cached/skipped tasks are never questioned.

Regression tests:
`option_targets_omit_selected_tasks_outside_the_runnable_rows` and
`option_targets_skip_cached_rows_until_they_are_marked_for_rebuild`.

### Dynamic choice and free-form answer

The exact matching run/request/generation owns submission. A preset choice
produced `accepted Repository · run resumed`. A physical Warp multiline Other
paste displayed `⟪paste #1 · 2 lines · 22 chars⟫`, submitted once, and produced
only `accepted free-form answer · run resumed`. Searches for `alpha beta` and
`gamma delta` found no match under the target `.kuzushi`; canonical agent run
input contains the operator task/question but not the answer text. This is the
intended sensitive-value lineage: delivery is process-local and the durable
receipt is categorical, not secret-bearing.

### Verification identity: requested finding fingerprint

The frozen final-5 journey prepared
`secret-scan:openai-api-key:0fc53b67956bf3f7`, but the deterministic model
returned `deterministic-audit-fingerprint`. The old normalizer accepted that
different identity and completed a verification result that did not update the
requested finding. The repaired adapter distinguishes absence from invalid
presence: an omitted fingerprint inherits the requested identity; an exact
match is accepted; a nonempty mismatch, empty/whitespace string, null, number,
or other non-string is rejected before persistence or phase advance. Errors
describe the shape/mismatch without logging free-form proof text.

Focused proof covers all twelve normalization branches, including the repair
pass. The final-7 terminal replay exercises mismatch, empty, null, omitted, and
exact-match cases against a fresh native finding and inspects the prepared
input, result artifact, finding proof projection, and restart.

### Finding discovery identity: execution run to patch/replay

Before the fix, Secret Scan stored the finding under an engine-local UUID while
the canonical run bundle—and its detector input—used the outer shell run ID.
`patch:finding` therefore refused the displayed finding because its discovery
ID had no replayable input artifact. The generic finding writer now accepts an
explicit canonical run ID, and `ToolExecutionContext::finding_run_id()` uses
the trace/run artifact identity for every mode with a direct-library UUID
fallback only when no run bundle exists.

The migration covers registry Secret/Dependency scan, Android adapters,
Semgrep/CodeQL/IaC, UAF Hunt, Variant NDiff, Chrome RCE, Prompt Armor, plugin
and Shinsa adapters, Exploit Chain, Full Mode, and Offense. Registry-level
tests assert that prepared/dispatched execution, returned `runId`, stored
`Finding.scan_id`, detector input path, proof `verification_run_id`, and replay
lookup all name the same canonical run. The final-7 journey must pass without
the synthetic copied run bundle used only to continue the pre-fix final-5
reproduction.

## Findings ranked by severity and operator impact

### F-01 — P1 — Result cards advertised keys that Prompt mode could not execute — FIXED

- Reproduce: open an unresolved Map result in Prompt mode; press literal `u`.
- Expected: either `u` selects the result or the card says how to reach the mode
  where it does.
- Actual: baseline advertised `u Use map`; the composer received `u` instead.
- Evidence: [`01-unresolved-map-result.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F02/01-unresolved-map-result.txt) and [`02-after-u-use-map.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F02/02-after-u-use-map.txt).
- Root cause / owner: `ui_view_models/phase_cockpit/mod.rs::phase_result_card`
  rendered result action labels without considering `InputMode`, while
  `app/state_transitions/key_dispatch.rs::handle_phase_result_key` intentionally
  accepts them only in Navigate.
- Fix: `phase_result_control_hint` now resolves the active keymap and displays
  `F2 Navigate...`, draft-blocked, or unbound copy in Prompt; Navigate alone
  displays action keys.
- Regression: `phase_result_card_discloses_controls_for_the_active_input_mode`,
  remapped/unbound tests, and 40-column header renderer test.

### F-02 — P1 — A visibly accepted descriptor value was never executed — FIXED

- Reproduce: on a context-built target, choose a cached context task, enter
  Other `sampleLimit=37`, accept the displayed acknowledgement, then launch.
- Expected: the task runs with 37, or the UI never asks the option.
- Actual: only CodeQL ran and no run input contained 37.
- Evidence: baseline [`29-after-37-accepted.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F03/29-after-37-accepted.txt) followed by [`30-accept-defaults-a.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F03/30-accept-defaults-a.txt).
- Root cause / owner: `app/guided_scan/options.rs::guided_option_targets`
  walked selected rows instead of the exact execution plan.
- Fix: option targets now derive from `build_execution_plan(tasks, selected,
  rebuild)`; cached and non-runnable rows are absent unless explicitly rebuilt.
- Regression: both `option_targets_*` tests plus the post-fix journey.

### F-12 — P1 — Accepted integer values were silently rewritten by the executor — FIXED

- Reproduce: run the baseline binary against F13 with
  `secret-scan:scan --input '{"maxFileBytes":1}' --plain`.
- Expected: descriptor validation refuses an unsupported value before executor
  work. If the headless driver has already minted an audit run, that run must
  end `failed` with the exact validation error; execution must not substitute a
  different value.
- Actual: the command completed, canonical `input.json` recorded `1`, and the
  scan reported an OpenAI key from a file larger than one byte because the
  executor silently raised the limit to 1,024. Negative input was ignored and
  fell back to 524,288; values above 64 MiB were silently reduced.
- Evidence:
  [`01-baseline-accepts-1.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F13-range-lineage/01-baseline-accepts-1.txt)
  and final-3
  [`02-fixed-rejects-1.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F13-range-lineage/02-fixed-rejects-1.txt).
  The post-fix run `run-1784070063-62f48a4f2899` is durably `failed`; its trace
  ends `refused` and its result contains no scanner findings.
- Root cause / owner: `modules/descriptor/descriptor_model.rs::OptionSpec`
  carried only integer type, not range; `modules/options/coerce_int_option.rs`
  accepted any JSON integer; and
  `scan/engines/secret_scan/scanner_options.rs::apply_limits` used `as_u64`
  plus `clamp`, losing negative and out-of-range operator intent.
- Fix: additive inclusive `minimum`/`maximum` descriptor metadata is enforced
  by canonical coercion and propagated by the trusted Node bridge. Secret Scan
  declares 1,024–67,108,864 bytes and 1–10,000 findings. Its executor uses
  `bounded_u64` and returns an error instead of rewriting input.
- Regression: focused TUI retention/canonical-preparation tests, registry range
  tests, executor rejection tests, an executed 2 KiB file-limit test, dynamic
  metadata tests, and KWP host projection tests.

### F-03 — P1 — Module Other replaced intent and advanced without confirmation — FIXED

- Reproduce: keep recommended secret-scan + semgrep, Tab Other, enter CodeQL.
- Expected: add canonical CodeQL, show the resulting set, wait for Continue.
- Actual: baseline replaced the set/advanced directly into unrelated options.
- Evidence: baseline F03 captures 10–23; fixed [`06-additive-ack.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F03-current-fixed/06-additive-ack.txt).
- Root cause / owner: `app/guided_scan/other.rs::submit_module_selection_other`
  treated free-form resolution as a completed selection transition.
- Fix: build and validate an additive proposed selection, keep the module card
  open, focus Continue, and acknowledge canonical labels/count.
- Regression: additive/unavailable module Other tests.

### F-04 — P1 — Other editors lost terminal input semantics — FIXED

- Reproduce: in guided Other use Ctrl+W/Alt+Backspace and multiline paste; in
  Warp paste CR-only multiline text into dynamic Other.
- Expected: cursor-aware deletion and a lossless visible paste with no submit.
- Actual: guided word deletion was a no-op, its multiline paste flattened
  lines, and Warp CR-only separators were deleted by the shared normalizer.
- Evidence: baseline [`14-other-word-delete.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F03/14-other-word-delete.txt), [`19-other-multiline-paste.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F03/19-other-multiline-paste.txt), and Warp fixed screenshot [`04-warp-multiline-paste-placeholder.png`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/Warp-F11-fixed/04-warp-multiline-paste-placeholder.png).
- Root cause / owner: guided flow stored an ad hoc string and modifier guards
  ran before the editor; `state_transitions/text_input.rs::normalise_paste_text`
  removed standalone CR.
- Fix: shared `EditorState`, editor-first key ownership, word/cursor actions,
  explicit multiline placeholders, and CRLF/CR → LF normalization.
- Regression: guided Shift/word/paste tests,
  `paste_normalisation_preserves_cr_only_terminal_line_breaks`, and physical Warp.

### F-05 — P1 — Dynamic questions contradicted run state and captured attention at the wrong locus — FIXED

- Reproduce: launch the dynamic question fixture in Run Focus.
- Expected: nonterminal waiting state and card beside the bottom input locus.
- Actual: header said `✓ COMPLETE` while body said WAITING INPUT at the top,
  followed by a blank canyon; Other editing still advertised selection keys.
- Evidence: [`02-question-foreground.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F11/02-question-foreground.txt) and fixed [`01-question-bottom-197x69.png`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/Warp-F11-fixed/01-question-bottom-197x69.png).
- Root cause / owner: `ui_view_models/activity_view.rs` had no waiting outcome;
  Activity rendered the question among body lines; question hints did not branch
  on editor state.
- Fix: `ActivityRunOutcome::WaitingForOperator`, a bottom input allocation with
  compact 40×12 projection, and editor-specific hints.
- Regression: waiting header/observability tests,
  `operator_question_renders_beside_bottom_input_locus_at_40x12`, and compact
  prompt/selection/next-action tests.

### F-06 — P1 — Background question hid the Map composer while accepting invisible input — FIXED

- Reproduce: press `b` on a waiting dynamic question, type `jobs` on Map.
- Expected: Map composer visibly owns the draft; waiting work stays in attention
  chrome and never overlays workflow input.
- Actual: a one-row question renderer covered the composer. `jobs` was stored
  invisibly and executed on Enter.
- Evidence: baseline [`08-jobs-draft.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F11/08-jobs-draft.txt) and fixed [`02-background-map-composer-visible.png`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/Warp-F11-fixed/02-background-map-composer-visible.png).
- Root cause / owner: `renderer/views/activity/operator_question.rs::render_operator_question_input`
  lacked the `ShellView::Activity` ownership guard already present in its height
  helper.
- Fix: render only when Activity is the current shell view and its active view
  model owns the matching question.
- Regression: `background_question_preserves_the_workbench_composer_draft`.

### F-07 — P2 — Accepted dynamic answers disappeared behind the final receipt — FIXED

- Reproduce: submit a fast dynamic choice.
- Expected: immediate visible canonical acknowledgement that survives the
  terminal receipt long enough to verify the answer.
- Actual: the success notice was replaced before a rendered frame.
- Evidence: fixed [`03-answer-acknowledged-and-map-restored.png`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/Warp-F11-fixed/03-answer-acknowledged-and-map-restored.png) and [`05-freeform-sanitized-ack.png`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/Warp-F11-fixed/05-freeform-sanitized-ack.png).
- Root cause / owner: `runtime_event_drains.rs::surface_operator_question_completion`
  emitted an ephemeral notice that terminal run finalization overwrote.
- Fix: retain a sanitized acknowledgement in `ActivitySession`, project it in
  the Activity feed, and append it to the final run receipt.
- Regression: immediate notice, final receipt retention, feed retention, and
  free-form redaction tests.

### F-08 — P1 — Clean Scan `next` ignored the Report destination — FIXED

- Reproduce: reopen F10 after completed current-revision zero-finding Scan;
  type literal `next`, Enter.
- Expected: Report, exactly as the NEXT strip advertises.
- Actual before fix: Guided Scan opened and said `Fresh target — no prior
  Kuzushi state`.
- Evidence: [`02-next-opens-guided-scan-BUG.ansi`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/tmux/02-next-opens-guided-scan-BUG.ansi).
- Root cause / owner: `app/command_router/command_effects.rs::open_next_phase_picker`
  ignores `journey.destination` and always calls `open_phase_picker(journey.current)`.
  `ui_view_models/journey.rs::destination_next_action` is correct, and
  `key_dispatch.rs::open_rederived_journey_destination` already has the correct
  destination branch.
- Fix: route both the typed command and keyboard transition through the same
  destination-aware transition. A Report destination now opens Report directly.
- Regression: `next_command_opens_report_for_clean_scan_destination` and the
  fixed-2 detached PTY captures
  [`02-next-draft.ansi`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/final2/02-next-draft.ansi) and
  [`03-next-opens-report.ansi`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/final2/03-next-opens-report.ansi).

### F-09 — P2 — Report Esc lost the Scan origin — FIXED

- Reproduce: from F10 Scan, run `report`, then Esc.
- Expected: exact Scan page and input mode.
- Actual before fix: `VIEW FIX · REALITY SCAN`.
- Evidence: [`05-report-escape-return.ansi`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/tmux/05-report-escape-return.ansi).
- Owning boundary: Report navigation/origin restoration, not phase reality; the
  reality chip correctly stays Scan.
- Fix: capture a typed `ReportOrigin { view, input_mode }` before opening
  Report; Esc and `q` consume it and restore both fields exactly. Originless
  legacy opens retain the prior Fix fallback.
- Regression: `report_escape_and_q_restore_the_exact_scan_origin`; fixed-2
  [`04-esc-restores-scan-prompt.ansi`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/final2/04-esc-restores-scan-prompt.ansi) and
  [`05-q-restores-scan-prompt.ansi`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F10-clean-zero/final2/05-q-restores-scan-prompt.ansi).

### F-10 — P2 — Zoom hid the pane-cycle key while pane cycling remained possible — FIXED

- Reproduce: open a populated Review page in Navigate mode, focus Findings,
  press `Z`, then inspect the footer and press Tab.
- Expected: the zoom banner's advertised `Tab pane` remains bound and moves
  focus; zoom follows the new semantic surface.
- Actual before fix: zoom reduced `plan.surfaces` to one, so the key-disclosure
  layer removed Tab before the cycle handler could run.
- Root cause / owner:
  `app/state_transitions/view_keybinding_groups.rs::workbench_keybindings`
  counted rendered surfaces instead of `PhasePresentationPlan.available_surfaces`.
- Fix: pane-cycle disclosure now uses the available semantic surface count;
  rendering and hit-test geometry remain zoomed.
- Regression: `workbench_zoom_follows_tab_and_resets_on_exit` passes. This
  change does not move, resize, or replace the Map/composer geometry.

### F-11 — P1 — Ultra-compact Prove clipped `STATUS` and `NEXT` — FIXED

- Reproduce: render a selected Prove finding at 40×12.
- Expected: finding identity, proof meter, `STATUS`, and the next command remain
  visible in that order.
- Actual before fix: adaptive composition represented the planned ProveStatus
  surface as a synthetic zoom; `confirm::render` took the full status renderer
  before its compact branch, leaving only identity/summary rows.
- Root cause / owner:
  `renderer/views/workbench/phase_pages/mod.rs::render_phase_cockpit_body` and
  `phase_pages/confirm.rs::render` conflated planned surface selection with a
  user-requested focused zoom.
- Fix: `PhaseRenderState` carries layout density; sparse, focused, and guided
  ProveStatus at compact dimensions use the critical three-line
  identity/STATUS/NEXT projection before zoom dispatch. Ultra-compact focused
  mode folds `ZOOM` into the pane title instead of consuming a separate row,
  and the shared planning/render geometry makes the same decision.
- Regression: normal, explicit zoom, and unresolved ResultReady 40×12 Prove
  tests plus the canonical `phase_prove_40x12.snap`. The ResultReady fixture is
  backed by a current-target `PhaseAttemptLedger`, not an unreachable guided
  state. Final-3 detached captures are
  [`01-prove-normal-40x12.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F11-final3-compact/01-prove-normal-40x12.txt),
  [`02-prove-zoomed-40x12.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F11-final3-compact/02-prove-zoomed-40x12.txt), and restart-restored
  [`04-prove-result-ready-after-restart-40x12.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F11-final3-compact/04-prove-result-ready-after-restart-40x12.txt).

### F-13 — P1 — An unresolved partial result competed with instructions to rerun Scan — FIXED

- Reproduce: launch the canonical F14 unresolved `scan/partial` attempt at
  80×24 before acknowledgement.
- Expected: one authoritative next action—acknowledge the partial result—with no
  scanner launch or generic phase-continuation instruction competing for
  attention.
- Actual before fix: the global strip said `run discovery-only scanners and
  select a completed attempt` while the result card said `acknowledge the
  partial Scan`. After that copy was aligned, the same screen still displayed
  `run sast:scan {} scan now · next continue workspace phase`.
- Evidence: final-3
  [`01-partial-result-prompt.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F14-partial-final3/01-partial-result-prompt.txt)
  and intermediate final-4
  [`01-unresolved-prompt.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F14-partial-final4/01-unresolved-prompt.txt).
  The complete post-fix proof is the final-5
  [`AUDIT-RECORD.md`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F14-partial-final5/AUDIT-RECORD.md).
- Root cause / owners:
  `ui_view_models/journey.rs::destination_next_action` ignored the unresolved
  typed attempt, and
  `renderer/views/workbench/phase_pages/header.rs::command_hint_lines` rendered
  phase command hints even when `EngagementHeaderModel.result_card` owned
  attention.
- Fix: journey projection now prioritizes an unresolved partial
  acknowledgement, reuses it for summary copy, and blanks `next_tools`.
  Phase command hints are suppressed for every unresolved result card and
  return immediately after resolution.
- Regression:
  `unresolved_partial_scan_acknowledgement_outranks_generic_next_action`,
  `accepted_clean_scan_keeps_report_destination`,
  `unresolved_partial_result_suppresses_phase_command_hints`, and
  `normal_scan_retains_phase_command_hints`, plus the final-5 detached replay.

### F-14 — P1 — Activity accepted a completely invisible Prompt draft — FIXED

- Reproduce: open Activity from Review, press Esc to enter Prompt mode, then
  type literal `jobs` without Enter at 100×30, 120×36, or 40×12.
- Expected: the Activity composer and `jobs` draft remain visible at the bottom
  before submission.
- Actual before fix: every printable byte entered the shared composer, and
  Enter opened Jobs, but Activity rendered no composer row at any tested size.
- Evidence: pre-fix
  [`09-activity-prompt-jobs-draft.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F15-modal-origin-final3/09-activity-prompt-jobs-draft.txt),
  [`12-activity-invisible-draft-120x36.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F15-modal-origin-final3/12-activity-invisible-draft-120x36.txt),
  and post-fix
  [`06-activity-visible-jobs-draft-40x12.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F15-modal-origin-final4/06-activity-visible-jobs-draft-40x12.txt).
- Root cause / owner: `renderer/render_app.rs::prompt_height` unconditionally
  returned zero for `ShellView::Activity`, even after key dispatch changed
  `InputMode` from Navigate to Prompt.
- Fix: only `(Activity, Navigate)` suppresses the generic row. Guided and
  dynamic question surfaces still win first; `(Activity, Prompt)` reserves the
  normal bottom composer.
- Regression: `run_focus_navigation_owns_input_while_prompt_reserves_composer_row`,
  `activity_prompt_draft_is_visible_at_compact_and_wide_sizes`, and final-4
  detached captures at all three widths.

### F-15 — P1 — Contextual replacement corrupted the later back destination — FIXED

- Reproduce: Review/Prompt → Activity → Jobs → Esc to Activity, then
  submit `back`; separately replace Replay with Trace and Jobs before Esc.
- Expected: Esc restores the one exact contextual origin, and subsequent back
  continues beneath it to Review. Replacement never creates nested origins or
  durable mutations.
- Actual before fix: Activity was restored visually, but the next redraw
  recorded departed Jobs in history; `back` reopened Jobs instead of Review.
- Evidence: pre-fix
  [`14-back-from-activity-reopened-jobs.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F15-modal-origin-final3/14-back-from-activity-reopened-jobs.txt)
  and post-fix
  [`10-back-restored-review-prompt-40x12.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F15-modal-origin-final4/10-back-restored-review-prompt-40x12.txt),
  with the full chain in
  [`AUDIT-RECORD.md`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F15-modal-origin-final4/AUDIT-RECORD.md).
- Root cause / owners: `NavigationRouteState::sync_view_change` treated
  contextual decks as ordinary destinations, while
  `restore_contextual_surface_origin` did not accept the restored origin as the
  synchronized destination.
- Fix: the shared contextual-surface classifier is now the single policy;
  contextual decks are history-transparent, restoration accepts the exact
  origin, and `go_back` no longer duplicates that acceptance.
- Regression: `contextual_decks_leave_activity_back_history_pointing_at_review`,
  the contextual utility suite, repeated-back regression, and the final-4
  detached replacement journey. Phase-attempt and every run-artifact hash were
  unchanged before/after.

### F-16 — P1 — A long Other draft hid the active editing locus — FIXED

- Reproduce: on the missing-context prerequisite, Tab into Other and paste 512
  characters without submitting.
- Expected: the draft segment around the cursor remains visible so the operator
  can verify and correct the value.
- Actual before fix: head-only fitting kept the beginning and pushed the cursor
  beyond the rendered line; the interface accepted input that it no longer
  showed at the active locus.
- Evidence: pre-fix
  [`36-context-long-512-paste-visible.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F05-context-card-final5/36-context-long-512-paste-visible.txt)
  and post-fix
  [`05-long-512-paste-visible.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F05-context-card-final6/05-long-512-paste-visible.txt).
- Root cause / owner:
  `renderer/views/workbench/guided_scan.rs::append_other_editor` fitted one
  cursor-marked string from the head and did not use the shared editor viewport.
- Fix: render through `prompt_segments`, using display-column-aware head/tail
  budgets centered on the cursor. The shared text helpers handle double-width
  Unicode and multiline placeholders.
- Regression: long ASCII at compact/wide inner widths, double-width Unicode,
  multiline placeholder cursor, and the final-6 literal bracketed-paste replay.

### F-17 — P1 — Jobs said running while Run Focus said canceling — FIXED

- Reproduce: cancel a live Semgrep job while bounded cleanup keeps the worker
  slot alive; inspect Jobs and Run Focus before cleanup finishes.
- Expected: both authoritative views say `canceling` until terminal cleanup.
- Actual before fix: Jobs hardcoded `running`; Run Focus correctly showed
  `1 × canceling` and the footer said to wait for cleanup.
- Evidence: pre-fix
  [`38-queued-live-canceling.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final5/38-queued-live-canceling.txt)
  versus final-6
  [`07-jobs-live-canceling.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/07-jobs-live-canceling.txt)
  and [`08-run-focus-canceling.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/08-run-focus-canceling.txt).
- Root cause / owner: `ui_view_models/jobs_registry.rs::live_run_row`
  always projected `JobRunStatus::Running` and had no canceling state.
- Fix: derive Jobs status from the authoritative Activity task state and the
  shared scan/tool/worker cancellation tokens; render canceling with warning
  tone until the terminal event releases the slot.
- Regression: `jobs_and_run_focus_agree_while_live_run_is_canceling`, worker
  canceling projections, and the final-6 detached journey.

### F-18 — P1 — Pending Jobs identifiers changed after queue mutation — FIXED

- Reproduce: queue two commands, note `queued-1`/`queued-2`, cancel the first,
  then issue a delayed `jobs -k queued-1` intended for the old row.
- Expected: displayed identifiers remain stable; a stale selector cannot target
  a different newer command.
- Actual before fix: the second row was positional and immediately became
  `queued-1`, so a delayed command could cancel the wrong work.
- Evidence: final-5
  [`36-queued-after-cancel-queued1.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final5/36-queued-after-cancel-queued1.txt)
  renumbers license; final-6
  [`05-after-drop-queued1.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/05-after-drop-queued1.txt)
  retains `queued-2`, and capture 06 proves stale `queued-1` is harmless.
- Root cause / owner: `app/steer_queue.rs::synthetic_id` derived identity from
  the current VecDeque index during every render.
- Fix: assign a monotonic selector at enqueue time and retain it through FIFO
  pop, removal, drain, rendering, and cancellation lookup.
- Regression: `selectors_do_not_renumber_after_remove_or_drain`, Jobs row
  projection coverage, and the final-6 literal delayed-cancel replay.

### F-19 — P1 — Canceled and interrupted engines rendered as failed — FIXED

- Reproduce: reopen the canceled Scan attempt after cleanup.
- Expected: result card, Jobs, run summary, failure handoff, event, and trace all
  preserve the terminal identity `canceled`.
- Actual before fix: durable artifacts said canceled, but the recorded-engine
  row normalized every unknown non-success status to `failed`.
- Evidence: final-6
  [`10-scan-canceled-result-identity.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/10-scan-canceled-result-identity.txt)
  plus `ASSERTIONS.txt` for matching run/failure/event/trace values.
- Root cause / owner:
  `ui_view_models/phase_cockpit/scan/attempt.rs::normalized_engine_outcome`
  omitted canceled and interrupted branches.
- Fix: project `canceled`/`cancelled` and `interrupted` explicitly; no execution
  or durable status is rewritten by presentation.
- Regression: `canceled_and_interrupted_runs_keep_their_terminal_identity` and
  the final-6 restart/result journey.

### F-20 — P1 — Verification accepted a different finding identity — FIXED

- Reproduce: verify fingerprint
  `secret-scan:openai-api-key:0fc53b67956bf3f7` while the bridge returns
  `deterministic-audit-fingerprint`.
- Expected: a present identity must exactly match the requested finding; invalid
  output stays unresolved and receives a precise error.
- Actual before fix: the verify run completed under the bridge identity while
  the requested finding remained unverified.
- Evidence: final-5 Prove/Fix
  [`AUDIT-RECORD.md`](/private/tmp/kuzushi-operator-contract-audit-019f621b/remaining-prove-fix/AUDIT-RECORD.md)
  and its captures 01–04.
- Root cause / owner:
  `verification/adapters/verify_finding_result.rs::required_verification_fields`
  trusted any model-provided fingerprint; a first repair still treated
  empty/null/non-string presence as omission.
- Fix: only an absent key inherits the requested identity. Exact presence is
  accepted; mismatch, empty/whitespace, null, numeric, and other non-string
  shapes are hard errors before persistence.
- Regression: twelve adapter tests, including repair, mismatch and invalid
  shapes; the final-7 deterministic terminal replay covers visible correction
  and success paths.

### F-21 — P1 — Finding writers broke detector input and replay lineage — FIXED

- Reproduce: run native Secret Scan, then request `patch:finding` for its
  displayed fingerprint.
- Expected: `Finding.scan_id` names the canonical outer detector run containing
  the exact prepared input.
- Actual before fix: the finding used an engine-local UUID while the run bundle
  used `run-…`; patch refused with `requires a canonical detector run and input`.
- Evidence: final-5 Prove/Fix capture 04 and the lineage section in its
  [`AUDIT-RECORD.md`](/private/tmp/kuzushi-operator-contract-audit-019f621b/remaining-prove-fix/AUDIT-RECORD.md).
- Root cause / owners: generic and specialist persistence helpers minted UUIDs
  below `ToolExecutionContext`; final sweep found the same bypass in
  `full_mode_config_paths.rs::persist_full_mode_report` and
  `offense/persistence.rs::persist_chain_finding_for_run`.
- Fix: canonical run identity is passed into generic persistence and derived
  from `ToolExecutionContext::finding_run_id()` everywhere a run bundle exists;
  direct library callers alone retain a generated fallback. Offense finding and
  proof identities now share the replayable outer run.
- Regression: registry Semgrep, generic writer, UAF, Variant, Full Mode, Offense,
  and canonical-run suites; the final-7 journey must patch without a synthetic
  copied run directory.

### F-22 — P1 — Result cards advertised Esc but swallowed it — FIXED

- Reproduce: open an unresolved result in Navigate and press literal Esc.
- Expected: the advertised key enters Prompt without resolving or discarding
  the result.
- Actual before fix: the result owner consumed Esc, leaving Navigate unchanged.
- Evidence: final-5 Prove/Fix capture 12; final-6 captures
  [`11-result-navigate-before-default-esc.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/11-result-navigate-before-default-esc.txt)
  and [`12-result-after-default-esc-prompt.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/12-result-after-default-esc-prompt.txt).
- Root cause / owner:
  `app/state_transitions/key_dispatch.rs::reduce_phase_result_or_shell_key`
  consumed unhandled result-card keys before normal mode dispatch.
- Fix: configured result actions retain first refusal; the configured composer
  Prompt action and default unmodified Esc are then handled inside result
  ownership. Other text remains consumed, never leaked to the composer.
- Regression: default and remapped Prompt-mode result tests plus final-6/final-7
  literal-key journeys.

### F-23 — P1 — Jobs displayed an agent ID that could not cancel the job — FIXED

- Reproduce: while an agent waits for input, copy the compact Jobs row ID
  `529be6d7` and submit `jobs -k 529be6d7`.
- Expected: the exact advertised identifier targets that live generation.
- Actual before fix: Jobs replied `is not running`; the same job remained
  `WAITING INPUT` and durably running.
- Evidence: pre-fix and post-fix records at
  [`F20 final5`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F20-jobs-agent-display-id-final5/AUDIT-RECORD.md)
  and [`F20 final6`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F20-jobs-agent-display-id-final6/AUDIT-RECORD.md).
- Root cause / owners: cancel resolution recognized only literal `agent`, while
  Jobs rendered the Activity run ID; the test-only JobHub cancellation flag also
  diverged from the production token after the agent view cleared.
- Fix: resolve exact/unique compact Activity run references for the Agent slot,
  and derive canceling from the authoritative JobHub cancellation token.
- Regression: `cancel_job_accepts_the_agent_id_displayed_by_jobs`,
  `canceled_agent_slot_stays_canceling_after_agent_view_is_cleared`, and the
  final-6 `WAITING INPUT → canceling → canceled → restart` journey.

### F-24 — P2 — A remapped Prompt key left a hardcoded Esc hint — FIXED

- Reproduce: hot-reload `composer.prompt_mode = ["x"]` on an unresolved result
  and enter Navigate.
- Expected: footer, bottom composer line, and dispatch all advertise/accept `x`.
- Actual in final-6: footer said `x prompt` and dispatch accepted x, but the
  composer still advertised `Esc prompt`; literal Esc was correctly a no-op.
- Evidence: final-6
  [`13-result-remapped-navigate.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F16-cancel-jobs-final6/13-result-remapped-navigate.txt)
  and final-7
  [`03-remapped-result-navigate.txt`](/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F21-phase-result-remap-final7/03-remapped-result-navigate.txt).
- Root cause / owner:
  `renderer/chrome/prompt/mod.rs::navigation_prompt_line` hardcoded Esc instead
  of consuming the runtime keymap already used by dispatch/footer.
- Fix: `ui_view_models/prompt.rs::navigation_prompt_text` resolves the live
  composer binding, including default, remapped, and unbound states.
- Regression: two keymap view-model tests and the final-7 detached journey;
  Map-bottom geometry was not changed.

## Terminal, size, palette, and projection matrix

| Cell | Result | Evidence |
|---|---:|---|
| 40×12 | PASS | Final-3 normal/zoom/ResultReady Prove retains identity, proof meter, STATUS, NEXT; final-4 Activity renders its draft; final-5 Map ends with `◇ MAP › map-bottom-final5` |
| 60×20 | PASS | `size-60x20.ansi`; J14 complete journey |
| 80×24 | PASS | `size-80x24.ansi`; final-5 partial acknowledgement; final-6 long editor/cancellation/stable queue; final-7 remapped result-key journey |
| 100×30 | PASS | Final-4 Activity composer and Replay → Trace → Jobs origin replacement journey |
| 120×36 | PASS | `size-120x36.ansi`; F03/F09/F10 journeys; final-4 Activity draft; final-6 waiting-agent cancellation/restart |
| 160×48 | PASS | `size-160x48.ansi` |
| Physical Warp Shift / BackTab / Cmd+V | PASS after paste fix | `Warp-F11` baseline and `Warp-F11-fixed` post-fix artifacts |
| `xterm-256color` | PASS | J15 uses indexed SGR, no RGB SGR |
| Truecolor | PASS | J15 truecolor capture uses RGB SGR and a non-color selection marker |
| High contrast | PASS | J15 high-contrast target/palette captures |
| Reduced motion | REVIEW | Captured; spinner freeze remains a visual comparison rather than an automated assertion |
| Plain / non-TTY | PASS | J16 summary/findings/tools/explicit-target matrix |

## Performance and reliability observations

### Measured

- Idle key-to-visible-composer timing in detached tmux, ten trials: 16.5–51.0
  ms, median 20.0 ms. This includes tmux capture/poll overhead and is not a
  renderer-only benchmark.
- Current dirty-repo Git metadata calls: `rev-parse` 10 ms, branch 10 ms,
  `status --porcelain` 110 ms; phase reconciliation can therefore spend about
  130 ms in Git alone before ledger fsync or SQLite work.
- A long tmux `send-keys -l` burst used while typing deterministic Prove/Fix
  commands took up to about 18 seconds before the full draft was visible. This
  path emits many individual KeyEvents and is not equivalent to bracketed
  paste, which was separately lossless and immediate enough for the audited
  editor flow. It is still evidence that a synthetic key-event storm can starve
  the final bytes behind redraw/background work.
- No p95 measurement under an event storm was completed.

### Source-backed risks

1. **P1: synchronous UI-thread durability and workspace refresh.** The update
   loop immediately executes effects; phase result handling can append/reload
   ledgers, call `sync_all`, run three Git subprocesses, and load up to 500
   SQLite rows before the next render. One background event can exceed the
   nominal 3 ms drain slice.
2. **P1: unbounded render projection before viewport slicing.** Workbench,
   recommendation, home, run-diff, trace, and Replay paths clone or parse full
   artifacts—up to 64 MiB—and build all rows before slicing the viewport.
3. **P2: target-picker worker storm.** Every cursor move can start a detached
   facts worker with Git/file scans. Generation checks reject stale results but
   do not cancel stale computation.
4. **P2: file-picker/completion cloning.** Up to 5,000 paths / 8 MiB can be
   cloned, deduplicated, and sorted repeatedly per keystroke/render.
5. **P2: hydration starvation.** Two stale non-cancellable workers can occupy
   both slots and delay the current target even though stale results cannot
   corrupt state.
6. **P3: unbounded editors.** Cursor/string operations and paste payloads are
   O(n) with no descriptor/surface-specific upper bound.

### Verified strengths

- One authoritative `JobHub` live slot, bounded event capacity, and generation
  filtering.
- Reliable blocking delivery for question/credential/terminal events; only
  nonterminal progress is explicitly droppable.
- Durable trace write precedes the capped live trace copy.
- Background questions do not take key focus after F-06.
- Waiting questions poll cancellation every 50 ms.
- Question controls and completions are stamped by run, request, and worker
  generation. Focused regressions prove that stale Resolve/Snooze/Cancel and a
  stale submitted completion cannot control or clear the newer question.
- Final terminal replays prove explicit partial-result acknowledgement and
  restart, the unchanged 40×12 bottom Map composer, visible Activity drafts,
  and history-safe contextual replacement.
- Controlled cancellation proves Jobs/Run Focus state agreement, process-group
  cleanup, stable queued selectors, exact-once successor drain, terminal
  canceled identity, compact agent-ID targeting, and restart reconstruction.
- Canonical persistence regressions cover generic and specialist finding
  writers; verification rejects stale/malformed identities before proof or
  patch state can mutate.
- Watcher debounce/overflow signaling, worker panic guards, watchdog generation
  checks, and terminal-session Drop restoration are present.
- Startup reconstructs workflow attempts, findings, context, scene, scope, and
  job summaries; orphan disk runs render as uncertain `running?`, not live.

## Remaining risk and untested behavior

- The final Prove/Fix terminal journey uses deterministic model bridges so it
  can assert exact value lineage without spending credentials. It does not
  prove a live paid-provider transport or provider-side retry behavior.
- Executor cancellation remains cooperative after dispatch; the type system
  does not force every builtin to observe it between bounded chunks.
- A process-local waiting question cannot resume after restart. Durable run
  reconstruction must project it as stale/interrupted, not silently waiting.
- Leading/trailing whitespace and every destructive shortcut were not repeated
  against every card. The shared editors, descriptor coercion, and at least one
  512-character real-terminal draft were exercised.
- Canonical writers populate `completedAtUnix` for terminal runs and all 45
  sampled bundles were correct, but the published run-summary schema does not
  conditionally require it for a hand-constructed terminal artifact. This is a
  low-severity persistence-hardening gap, not a reproduced operator mismatch.
- Warp was used for terminal-dependent input proof before the operator asked
  for zero focus stealing; all subsequent journeys were detached tmux. No
  further GUI automation is planned.

## Verification commands and current results

All commands below ran from the recorded repository/HEAD unless an absolute
frozen-binary path is shown.

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo test -p kuzushi-core secret_scan -- --nocapture` | PASS — 12 passed, 0 failed |
| `cargo test -p kuzushi-core dynamic_integer_ranges -- --nocapture` | PASS — 2 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib guided_scan -- --nocapture` | PASS — 40 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib operator_question` | PASS — 18 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib older_operator_question_generation_cannot_control_matching_run_and_request` | PASS — stale resolve/snooze/cancel all refused |
| `cargo test -p kuzushi-tui --lib stale_operator_completion_cannot_clear_matching_current_question` | PASS |
| `cargo test -p kuzushi-tui --lib ui_view_models::journey::tests` | PASS — 15 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib renderer::views::workbench::phase_pages::header::tests` | PASS — 6 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib contextual_` | PASS — 9 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib run_focus_prompt_tests` | PASS — 4 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib ultra_compact_ -- --nocapture` | PASS — 6 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib phase_presentation` | PASS — 7 passed, 0 failed |
| `cargo test -p kuzushi-tui --lib phase_composition_contract` | PASS — 5 passed, 0 failed; 120 profile buffers, 30 truecolor snapshots, 30 plain cases |
| `/usr/bin/time -p cargo test -p kuzushi-tui --lib --quiet` | PASS — 2,012 passed, 0 failed; 152.31 s test time, 152.51 s wall |
| `cargo clippy -p kuzushi-tui --lib -- -D warnings` | PASS |
| `cargo clippy -p kuzushi-core --lib -- -D warnings` | PASS |
| `pnpm exec vitest run tests/modules/kwp-host.test.ts` | PASS — 2 tests |
| `pnpm typecheck` | PASS |
| `pnpm exec biome check src/modules/types.ts scripts/kuzushi-dynamic-module-host.mjs tests/modules/kwp-host.test.ts` | PASS |
| `/usr/bin/time -p pnpm quality:crap-risk` | PASS — 365 changed code files; 20.76 s wall |
| `git diff --check` | PASS |
| `cargo rustc -p kuzushi-cli --bin kuzushi -- --emit=link=.../kuzushi-fixed-final5` | PASS — frozen hash `9ca0f5be…8e102` |
| `run-final3-compact-journey.sh` | PASS — normal/zoom Prove, Map bottom composer, restart ResultReady at 40×12 |
| Final-5 bottom Map composer replay | PASS — 40×12, `alternate_on=1`, `attached=0`, bottom row `◇ MAP › map-bottom-final5` |
| Final-5 F14 partial-result replay | PASS — aligned guidance, no conflicting hints, one acknowledgement, byte-identical restart ledger |
| Final-4 F15 Activity/modal-origin replay | PASS — visible drafts at 40×12/100×30/120×36; exact Esc/back origin; no durable mutation |
| Final-3 F13 `maxFileBytes=1` replay | Expected refusal — exit 1, precise lower-bound error, durable failed/refused run, no scanner result |

The durable full-suite record is
`/private/tmp/kuzushi-operator-contract-audit-019f621b/full-tui-test.result`;
final compact provenance is
`/private/tmp/kuzushi-operator-contract-audit-019f621b/captures/F11-final5-map-bottom/provenance.txt`.
