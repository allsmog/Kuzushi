# Cyber operator TUI experience audit — 2026-07-11

## Remediation update — 2026-07-11

**Current verdict: the UI/UX findings in this audit are cleared.** The original
screen-level evidence remains below as a historical record of the pre-fix
state; its `Hold for operator use` verdict is no longer the verdict for the
current working tree.

The remediation stayed on the shared Rust descriptor, execution, persistence,
and presentation boundaries instead of adding mode-specific exceptions:

| Finding | Resolution |
|---|---|
| F01 | Semgrep's metrics-off default now uses the explicit `p/security-audit` pack in descriptors, scan defaults, and prepared input. |
| F02 | Global reads fold by durable finding identity, merge corroborating sources, and preserve stable aliases/priorities across filtered exports. |
| F03 | Scanner-only Activity uses the execution receipt (`execution:none · runtime-free`) instead of presenting a configured cloud model as the runtime. |
| F04 | Unix scanners and descendants join a guard-owned process group with a parent-death lifeline; abrupt Kuzushi loss kills the whole group. Windows retains kill-on-close Job Object behavior. |
| F05 | Review supports arrows and `j/k`, retains filters across refresh, opens aliases on the Review/Confirm surface, and puts the durable human decision before verbose evidence. |
| F06 | Confirmation dispatch accepts real shifted uppercase confirmation keys; the quit modal now advertises only actions it implements. |
| F07 | Health renders one hydrated summary and distinguishes pending context from a live snapshot. |
| F08 | Boot preserves the identifying tail of long target paths instead of hard-clipping them into a different plausible path. |
| F09 | Esc from target consent opens targetless Capabilities with visible `target <path>` and `demo` recovery actions. |
| F10 | Compact Confirm preserves alias, title, location, and proof action; CLI demo copy points to persisted evidence without claiming rows were printed. |
| F11 | Non-empty recon results get a structured Activity Recon page, `o` opens full detail, and Replay rehydrates the same host/service/note evidence from `result.json`. |
| F12 | `permissions` has a dedicated scrollable policy view that separates enforced dispatch boundaries from shell pre-dispatch checks and explicitly disclaims OS sandbox status. |
| F13 | Planning keeps selection/launch controls visible at the common wide breakpoint as well as compact sizes. |
| F14 | Workspace derives one persisted-finding truth and retains `.kuzushi/v3` context in displayed state paths. |
| F15 | Footer bindings are input-mode aware: Prompt shows command actions; Navigate shows physical view keys. |
| F16 | Workbench command failures surface through a visible notice instead of only the hidden transcript. |
| F17 | A settled, unrequested strategy queue says it was not generated; terminal tool receipts distinguish an unrecorded run count from an unknown result. |
| F18 | Historical phase pages retain reality-derived global guidance and no longer tell an advanced workspace to restart an empty Map run. |
| F19 | Replay prefixes artifact state (`MISSING`, `INVALID`, and related states), reports omitted aliases, and Knowledge Base names the v3 store. |
| F20 | Activity and shared footers no longer advertise mutually exclusive Prompt and Navigate actions together. |
| F21 | Compact layouts reserve finding identity/location/action before secondary panels, clip list rows coherently, and emit one footer overflow pointer. |
| F22 | Update uses a neutral unchecked state until a release check has actually established availability. |

Post-fix verification on the integrated tree:

- `cargo test -p kuzushi-tui --lib --quiet`: **1,748 passed**.
- `cargo test -p kuzushi-core --lib --quiet`: **2,817 passed**.
- `pnpm quality:crap-risk`: **passed for 142 changed production files**.
- `cargo fmt --all -- --check` and `git diff --check`: **passed**.
- Live tmux replays at 100×30 and 60×20 verified Permissions, HTTPX import
  evidence in Activity and Replay, compact scrolling/footer behavior, and the
  corrected demo handoff.
- A real CLI fault replay sent `SIGKILL` to Kuzushi while a fake Semgrep wrapper
  and `sleep` descendant were active; the guard and complete scanner group
  exited. The CodeQL cancellation race regression also passed 50 consecutive
  repetitions.

The original pass below was an observation-only audit of the real Rust Ratatui
shell. The only repository file written by that observation pass was this
report.

## Original verdict (pre-remediation)

**Hold for operator use.** The phase cockpit is visually strong and several
control surfaces are genuinely trustworthy, but the full experience does not
yet clear the trust bar for a cyber operator. Three release-blocking failures sit
on the normal path:

1. the default Hunt plan asks Semgrep for its `auto` rules while also forcing
   metrics off, so an installed Semgrep makes the default plan fail;
2. one persisted finding can acquire different aliases and counts across CLI,
   Workbench, journey chrome, detail lookup, and export; and
3. the zero-model offline demo labels its completed result only with a
   configured cloud model, leaving actual execution provenance ambiguous.

These are not visual nits. They undermine execution, evidence identity, and the
operator's ability to know what ran. Abrupt process loss adds an operational
safety gap: a scanner can survive under PID 1 while the restarted Jobs view says
there are no live jobs.

The good news is equally concrete. Target consent, the inline credential gate,
live cancellation state, scoped job cancellation, autonomy refusal, export file
generation, command discovery, 256-color/high-contrast rendering, non-TTY
output, and the four phase compositions all worked in live tests.

## Method and scope

- Binary: `kuzushi 0.24.0-alpha.6 (e5879dfa7+dirty · debug)` at HEAD
  `e5879dfa7`.
- Driver: tmux 3.6a, real keystrokes, alternate-screen-aware plain captures and
  ANSI captures after each checkpoint.
- State: isolated `HOME`/XDG directories and fresh temporary Git targets for
  independent journeys.
- Sizes: 60×20, 80×24, 100×30, 110 columns, and 120×36.
- Terminals: `xterm-256color`, truecolor, high-contrast, reduced-motion, plain,
  and non-TTY pipe paths.
- Scanner: the installed Semgrep 1.165.0 was exercised. Local deterministic
  secret/IaC fixtures, fake long-running scanner processes, recon fixtures, and
  repeated scans were used where a live transition was required.
- Rubric: **Honesty > Intent/State > Craft**. A severity is `blocker` when the
  normal task cannot complete or evidence identity cannot be trusted; `stall`
  when a real operator is likely to stop or act on a misleading state;
  `friction` when recovery exists but is obscure; and `polish` for presentation
  defects without state risk.

Source was inspected only after a screen-level failure had been recorded. No
model-backed verify/patch run, real OAuth handshake, provider call, or live
network target was exercised.

## Findings

### F01 — The default Hunt plan cannot run with an installed Semgrep

- **Journey/checkpoint:** J4, Planning → run the default Hunt plan
- **Lens:** Intent, State, Honesty
- **Severity:** blocker

The normal plan ran the built-in secret scanner, persisted a credential, then
failed at Semgrep:

```text
Cannot create auto config when metrics are off. Please allow metrics or run
with a specific config.

✗ run failed · findings unknown
1 finding (1 high)
```

The screen therefore says both “findings unknown” and “1 finding,” after the
default action failed for an internally contradictory configuration. This is
not an absent-tool edge case: it happens specifically when Semgrep is available.

Likely cause: `SemgrepScanner::default()` selects `config: ["auto"]` in
`crates/kuzushi-core/src/scan/domain/scan_engine.rs:44`, while execution always
passes `--metrics off` and `SEMGREP_SEND_METRICS=off` in
`crates/kuzushi-core/src/scan/adapters/tool_input.rs:82`.

### F02 — Finding identity and counts split across five operator surfaces

- **Journey/checkpoint:** J4 finding drill, J5 export, J7 review
- **Lens:** Honesty, State
- **Severity:** blocker

Running the same secret scan twice produced eight stored rows in the CLI, four
durable identities in Workbench, and three simultaneous totals in one TUI:

```text
NEXT  triage & verify — 8 of 8 findings need review
REVIEW QUEUE · 4
4 findings / 4 high
```

Pairs shared the exact fingerprint and location. Alias lookup could not preserve
the identity shown by list/export:

```text
$ kuzushi finding F-0002
Finding F-0001
Alias: F-0001

$ kuzushi finding F-0004
Finding F-0003
Alias: F-0003
```

Completeness filtering also renumbered a PEM finding from `F-0005` in the
workspace to `F-0001` in the open-only export. An operator cannot safely cite,
review, suppress, or submit an identifier that changes at projection time.

Likely cause: export filters records before calling the alias projection in
`crates/kuzushi-core/src/workspace/application/export_workspace_findings.rs:149`,
then recomputes aliases by enumerating the filtered slice in
`crates/kuzushi-core/src/workspace/application/export_projection.rs:37`.

### F03 — The offline demo makes execution provenance ambiguous

- **Journey/checkpoint:** J1 credential gate → `d`; J2 offline demo; J14 compact
  launch
- **Lens:** Honesty
- **Severity:** blocker

The credential screen promises:

```text
Offline demo · run bundled fixture now; no key, model, or scanner binary
```

The completed deterministic run then labels itself:

```text
target:./kuzushi-demo · ctx:not built · model:openai:gpt-5.5 · 7 findings
```

The same happened after choosing Claude; at 60 columns it degraded to
`model:anthropic:`. A privacy-sensitive evaluator cannot tell whether this is a
configured-but-unused selector or the runtime that processed the repo. The
finding is that ambiguity; this audit did not infer a provider call from the
label.

Likely cause: picker acceptance stores `config.model` before credential
resolution (`crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:168`),
and the context strip renders that configuration without the execution receipt
(`crates/kuzushi-tui/src/ui_view_models/context_strip.rs:93`).

### F04 — A scanner can survive process loss while Jobs says none are live

- **Journey/checkpoint:** J9, kill Kuzushi during a long-running scanner and
  restart
- **Lens:** Honesty, operational safety
- **Severity:** stall

After `SIGKILL`, restart repaired the run row:

```text
08e4b6d2    tool      interrupted  20s
no live jobs — recent runs shown
```

The scanner and its child were still running:

```text
5668  1     S  /bin/sh .../semgrep --metrics off --json ...
5669  5668  S  sleep 120
```

Normal in-shell scoped cancellation did reap the addressed run and preserved the
queued unrelated job. The gap is abrupt shell loss: the recovered metadata is
honest about interruption but Jobs cannot reveal or control the surviving work.

### F05 — Review navigation and durable decision state disagree

- **Journey/checkpoint:** J7, move among findings and record decisions
- **Lens:** State, Intent, Honesty
- **Severity:** stall

`j/k` moved the visible cursor, but Down was inert. Pressing Esc to return to the
prompt visibly snapped selection back to the last Enter-pinned finding:

```text
F-0002 pinned
j   -> highlight F-0005
Esc -> highlight snaps to F-0002
decision ... -> applies to F-0002
```

The screen does not explain that movement is provisional until Enter pins the
row. Decisions did persist across restart, but detail then contradicted the
queue. An accepted-risk row still opened as:

```text
F-0002 HIGH ? signal-only candidate
lifecycle status: candidate
validate: `verify F-0002`
```

The queue says `risk`; the finding page never displays the human decision.
The active Workbench navigation path handles character `j/k` rather than arrows
in `crates/kuzushi-tui/src/app/view_state/workbench_nav.rs:69`.

### F06 — The advertised persistent approval key is unreachable

- **Journey/checkpoint:** supplementary approval-gate check encountered while
  preparing J8
- **Lens:** Intent, Honesty
- **Severity:** stall

The card advertises:

```text
y allow once   Y allow + remember
```

A real uppercase Shift+Y did not approve. It inserted `Y -> yes` into the prompt
and left the modal open. Lowercase `y` then launched the tool with the stray
input still visible. `confirm_key_ready` requires empty modifiers in
`crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:285`, so a real
Shift-modified uppercase key cannot reach the advertised action.

### F07 — Health renders three incompatible health summaries

- **Journey/checkpoint:** J13, `health`
- **Lens:** Honesty
- **Severity:** stall

One settled screen said:

```text
-- SUMMARY
  health: 3 failing, 3 warning

stage health: 3 failing, 3 warning
17:12:13 · health health: 0 failing, 7 warning
```

It also labeled context `ctx ✓ live` after Context and Project Model had shown
the snapshot missing. The route logs a model immediately after switching views
(`crates/kuzushi-tui/src/app/command_router/command_effects.rs:612`), while the
body can hydrate later; the default status hardcodes `ctx: "live"` in
`crates/kuzushi-tui/src/ui_view_models/health.rs:82`.

### F08 — Boot clips the target into a different plausible target

- **Journey/checkpoint:** J13, `boot` at 110 columns
- **Lens:** Honesty, State
- **Severity:** stall

The actual target ended in `target-j13`; Boot displayed:

```text
✓ workspace  /private/tmp/kzop-audit.yvo11M/target-j1
```

There is no ellipsis, so this reads as a different valid target rather than a
truncated one. Security tooling cannot hard-clip the identity of what it is
about to inspect. `fixed_width` takes the first N characters in
`crates/kuzushi-tui/src/renderer/views/system/overlay_lines.rs:252`.

### F09 — Esc from target selection creates a targetless dead-end

- **Journey/checkpoint:** J3, target picker → Esc
- **Lens:** Intent, State
- **Severity:** stall

Explicit consent itself is correct: cwd is offered and never silently selected.
After Esc, however, the new operator lands on:

```text
Kuzushi · target:no target · page:confirm · ○ idle

FINDING
∅ no finding selected
select a finding to inspect its path and proof
```

There is no visible `target <path>` action or way to reopen the picker. The
recovery instruction is written to the hidden transcript before Workbench opens
(`crates/kuzushi-tui/src/app/state_transitions/picker_keys.rs:239`).

### F10 — Demo output claims evidence that it never displays

- **Journey/checkpoint:** J2, `kuzushi demo`; J14 at 60×20
- **Lens:** State, Intent, Honesty
- **Severity:** stall

The CLI prints only a total and engine names:

```text
sast:scan ... completed: 7 finding(s)
Engines: secret-scan, iac-scan
demo: findings above record scanner signals, redacted locations, and an
demo: honest signal_only proof state
```

There are no finding rows “above,” no redacted location, and no proof-state row.
At 60×20 the TUI Confirm page also drops the title and location, leaving only an
alias, severity, and fragmented proof guidance. The first-wow route reports the
existence of value instead of showing one receipt. The CLI claim is static prose
in `crates/kuzushi-cli/src/application/demo.rs:34`; the compact Confirm layout
allocates percentage heights in
`crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/confirm.rs:164`.

### F11 — Recon import succeeds but its evidence is invisible in the TUI

- **Journey/checkpoint:** J6, `recon:import httpx <fixture>`
- **Lens:** State, Honesty
- **Severity:** stall

The persisted artifact correctly contained one host, TCP/443, and one note. The
settled operator surface instead said:

```text
activity is live; waiting for the first trace event
✓ run completed · findings unknown
```

Activity and Replay showed unrelated vulnerability aliases rather than the
imported host/service. Reachability is fixed—the command dispatches and data is
stored—but a cyber operator cannot validate the intake without leaving the TUI
and reading artifacts manually.

### F12 — `permissions` opens model configuration, not permission policy

- **Journey/checkpoint:** J13, `permissions`
- **Lens:** State, Intent
- **Severity:** stall

The screen becomes:

```text
KUZUSHI mode:module · view:config
── CONFIG ──
backend LangGraph
provider — none active
```

The actual policy appears only as two truncated transcript lines. The command
explicitly routes to `ShellView::Config` and logs prose in
`crates/kuzushi-tui/src/app/command_router/command_effects.rs:718`.

### F13 — Consequential planning controls vanish at 100×30

- **Journey/checkpoint:** J4, default Hunt planning at 100×30
- **Lens:** Intent
- **Severity:** stall

The screen lists RUN/SKIP tasks but omits the Space/Enter instructions and shows
only:

```text
command prompt paused — : to type a command
```

Enter launches every RUN row, including the broken Semgrep task. At 60×20 and
80×24 onboarding planning controls were visible, so the responsive behavior is
non-monotonic: the common larger size is less explicit about a consequential
action.

### F14 — Workspace says both zero and four persisted findings

- **Journey/checkpoint:** J5 missing export arguments → Workspace; J13
  `workspace`
- **Lens:** Honesty, State
- **Severity:** stall

One screen rendered:

```text
findings  none yet (run scan first)
FINDINGS ROLLUP · 4 persisted
4 high
```

It also reduced state/database paths to `./v3` and `./index.sqlite3`, discarding
the `.kuzushi` context. `workspace_model` obtains the first count from the domain
view but the rollup from `app.findings()` in
`crates/kuzushi-tui/src/ui_view_models/workspace.rs:39`; a missing domain count
is converted to “none yet” at line 109. `compact_target_path` keeps only the last
path component in `crates/kuzushi-tui/src/ui_view_models/display_text.rs:4`.

### F15 — The universal `Esc back` promise is not executable

- **Journey/checkpoint:** J11/J13, Logs, Workspace, and other ordinary views
- **Lens:** Intent, Honesty
- **Severity:** stall

In Navigate mode the footer simultaneously advertises:

```text
Esc prompt    Esc back
```

Esc always returns to Prompt mode. In Prompt mode with empty input, Esc does
nothing; typed `back` is required. The input-mode handler consumes Navigate Esc
first (`crates/kuzushi-tui/src/app/state_transitions/key_dispatch.rs:396`), while
`view_keybindings` adds `Esc back` to nearly every non-modal view
(`crates/kuzushi-tui/src/app/state_transitions/view_keybindings.rs:11`).

### F16 — Command errors can be invisible in the active Workbench

- **Journey/checkpoint:** J6/J11, load `recon:import` from the palette and run it
  without required arguments
- **Lens:** State
- **Severity:** friction

Executing the incomplete command left the Workbench body visually unchanged.
Only after navigating to Logs did the operator see:

```text
recon:import requires option tool...
```

By contrast, missing export arguments route to Workspace and show usage. Failure
receipts need one consistent, visible location instead of depending on whether a
command chooses to replace the body.

### F17 — Settled runtime chrome retains loading and unknown states

- **Journey/checkpoint:** J1/J2/J4/J14, completed local scans
- **Lens:** Honesty
- **Severity:** friction

Completed idle demo runs displayed:

```text
○ idle
strategy queue is loading
subsystems (23) queued
✓ run completed · 7 findings
```

The failed Semgrep composition similarly showed `findings unknown` beside
`1 finding (1 high)`. `NotRequested` and `Loading` are collapsed to the same
label in `crates/kuzushi-tui/src/ui_view_models/strategy_queue.rs:101`.

### F18 — Historical phase pages issue actions that current reality cannot honor

- **Journey/checkpoint:** supplementary J17, manually open Map after findings
- **Lens:** Intent, Honesty
- **Severity:** friction

Map was marked complete even though its body said:

```text
○ settled run no run
no map activity yet — use next to start
coverage 0/0
```

The global NEXT action was actually `triage & verify`, not Map. `next map target`
was also suggested. Manual phase navigation correctly preserved the
reality-derived Confirm phase, but page-local calls to action remained static
and therefore false for the current workspace.

### F19 — Trace and Knowledge Base hide important artifact truth at width

- **Journey/checkpoint:** J13, `trace` and `kb`
- **Lens:** State, Honesty
- **Severity:** friction

Trace listed long triage/verify paths whose files did not exist. The model does
append `(missing)`, but only after the full path; clipping removed the status, so
the visible line looked valid. It also showed only three of four aliases with no
“+1 more.” The projection uses `.take(3)` at
`crates/kuzushi-tui/src/ui_view_models/run_trace.rs:86` and appends state after
the display path at line 267.

Knowledge Base still said:

```text
kuzushi indexes attachments under .kuzushi/v2/artifact-kb.sqlite3.
```

That copy is hardcoded in
`crates/kuzushi-tui/src/renderer/views/workspace/knowledge_base_lines.rs:65`,
while the current workspace contract is v3.

### F20 — Footers advertise mutually exclusive actions without mode context

- **Journey/checkpoint:** J12 Scene; J13 Prompts; J17 Confirm
- **Lens:** Intent, Honesty
- **Severity:** friction

Prompt mode on Scene says:

```text
Tab complete   F2 nav mode   Tab next page
```

Tab opened command completion; only after F2 did it cycle all five pages. The
Workbench footer likewise shows both `Tab complete` and `Tab pane`; Prompts
repeats the same group as three actions:

```text
e/s/d/r edit   e/s/d/r show   e/s/d/r diff
```

The body correctly says `e edit · s show · d diff · r reset`. These surfaces
need input-mode-specific bindings, not simultaneous global and view-local
legends.

### F21 — Narrow layouts sacrifice finding identity before secondary panels

- **Journey/checkpoint:** J14 60×20/80×24 and J12 Activity
- **Lens:** State, Intent
- **Severity:** friction

At 60×20 Confirm retained empty Attack Path and Data-Flow sections while dropping
the finding title and location. At 80×24 Activity wrapped a title onto an
unindented next line:

```text
F-0003  H sig open
GitHu...
```

The title no longer reads as part of the row. The narrow footer also emitted
`help more` twice after wrapping. Compact design should preserve
identity/location/proof first, indent continuation rows, and add one overflow
affordance for the whole footer.

### F22 — Update claims availability without a configured check

- **Journey/checkpoint:** J13, `update`
- **Lens:** Honesty
- **Severity:** friction

One overlay says:

```text
UPDATE AVAILABLE
update check · not running from this shell
release feed not configured in the Rust shell
```

The body is honest but the highest-salience title is not. The title is hardcoded
in `crates/kuzushi-tui/src/renderer/views/system/overlay_lines.rs:146`.

## Journey results

| Journey | Result | Live verdict |
|---|---|---|
| J1 Keyless first launch | **Fail** | Target/model/credential/planning gates work, but offline completion shows only a configured model, leaving execution provenance ambiguous, and hides the promised receipt. |
| J2 Offline demo | **Fail** | Deterministic run completes; CLI claims a finding/location/proof presentation that it never prints. |
| J3 Explicit-target consent | **Fail** | Explicit consent is fixed; Esc truthfully chooses no target but offers no visible recovery. |
| J4 Scan to finding | **Fail** | Local findings persist, but the default Semgrep plan is impossible and finding aliases/counts diverge. |
| J5 Export | **Fail** | JSON, SARIF, CSV, JSONL, and Markdown bundle files are valid; discovery is weak and filtering renumbers aliases. |
| J6 Recon intake | **Fail** | `recon:import` is reachable and persists correct data, but Activity/Replay do not show the imported evidence. |
| J7 Triage/dismissal | **Fail** | Decisions persist, but provisional selection and stale detail state make the action target/result unclear. |
| J8 Interrupt mid-run | **Pass** | Live → canceling → canceled was honest, a second Ctrl+C was safe, and Jobs retained `canceled`; idle exit arming lacks visible acknowledgement. |
| J9 Jobs/steer | **Fail** | Queue advancement and scoped kill pass; abrupt shell loss leaves an unmanaged scanner while Jobs says no live jobs. |
| J10 Autonomy | **Pass** | Recon/Hunt/Confirm/Fix posture is truthful; blocked work says skipped and raising posture never forges phase progress. |
| J11 Discoverability | **Pass** | Grouped Help, 52 phase-grouped tools, primary module actions, and ranked palette search are navigable. |
| J12 Activity/viz | **Fail** | Content-gated auto-open and empty hints are honest; Scene's advertised Tab action is false until the operator infers F2. |
| J13 Deep view tour | **Fail** | Catalog-after-KB is fixed; Health, Permissions, Update, Boot, KB, Trace, and universal back chrome are not truthful. |
| J14 Narrow terminal | **Fail** | Gate mechanics work at 60×20/80×24; finding identity/location and result truth do not survive the compact layout. |
| J15 TERM/theme | **Pass** | 256-color uses indexed codes, truecolor uses RGB, high-contrast remains distinct, and selection is visible without relying on color alone. |
| J16 Plain/non-TTY | **Pass** | No ANSI leakage; useful Help/Jobs/Scene fallback; missing-target consent fails with exit 1 and explicit-target scan writes a complete run bundle. |
| J17 Phase cockpit (supplementary) | **Pass** | All four 120×36 compositions meet the phase contract and manual navigation does not forge journey progress; historical CTAs need reality-aware copy. |

## Prior-risk regression check

| Prior risk | Result now |
|---|---|
| Blank/stalled bare launch | **Fixed** — target gate appeared in under 0.5 seconds. |
| Credential dead-end | **Fixed** — inline API-key/OAuth/offline choice appears. |
| Silent cwd fallback | **Fixed** — Enter is required; Esc stays targetless. |
| Planning cropped at 60×20/80×24 | **Fixed at those sizes**, but controls disappear at 100×30. |
| Planning cursor loses the task window | **Fixed** in the onboarding runs. |
| `tool descriptor missing` during Planning | **Did not reproduce.** |
| Recon import unreachable | **Fixed for dispatch/persistence**; result observability remains a stall. |
| Canceled job becomes successful | **Fixed** — cancellation remained canceling/canceled. |
| Steer-queue starvation/scoped kill | **Fixed** under normal operation. |
| Flat 67-tool discoverability wall | **Improved** — 52 tools are phase-grouped and palette ranking works. |
| Empty viz auto-open | **Fixed** — empty scans stayed on Findings. |
| Catalog chrome after Knowledge Base | **Fixed.** |
| Truecolor-only palette | **Fixed** in the tested TERM matrix. |
| Plain-mode usefulness | **Pass.** |

## Top three functional issues an operator hits first

1. **Run:** the default Hunt action fails as soon as it reaches an installed
   Semgrep because `auto` and forced-off metrics are incompatible.
2. **Trust the evidence:** the same finding changes alias and aggregate count
   across list, queue, detail, and export.
3. **Evaluate safely:** the offline demo labels itself with a cloud model and
   claims to show evidence it does not render.

## Visual-craft summary

The onboarding gates and phase cockpit have a distinctive, restrained visual
language: cyan selection, yellow next-action emphasis, green completion,
severity tones, and strong pane composition. The four phase pages are the part
of the product I would be proud to open in front of someone.

The highest-leverage craft changes are:

1. make title, body, chrome, and event receipts consume one route-owned truth
   snapshot so a settled screen cannot contain competing statuses;
2. make footers input-mode aware—show completion bindings in Prompt mode and
   pane/page bindings in Navigate mode, never both;
3. preserve target and finding identity with middle ellipsis and prioritized
   compact layouts before rendering empty secondary panels;
4. keep wrapped finding titles visually attached to their alias row and apply a
   single overflow treatment to the complete footer; and
5. reduce heavy zebra backgrounds and large empty regions after the state model
   is coherent; styling is not the current bottleneck.

**Overall craft bar:** the cockpit clears it; the full TUI does not, because
exact target, execution, evidence, and health truth still fracture between
otherwise polished surfaces.
