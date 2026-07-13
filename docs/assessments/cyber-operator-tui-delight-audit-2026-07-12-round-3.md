# Cyber Operator TUI Delight Audit — Round 3

Date: 2026-07-12

Baseline binary: `kuzushi 0.24.0-alpha.7 (775a4134f+dirty · debug)`
Baseline SHA-256: `d36b9a7ee5e432684a93301fd7f1b49106dbb9c405ed581b099b153f9eda1c78`

## Outcome

This pass treated the terminal as an operator product, not a renderer demo. Three independent source-blind audits covered first use and learnability, the full finding-to-decision operator loop, and terminal craft/accessibility at 110×32, 80×24, 60×20, and 40×12. Every confirmed high-signal issue was traced to its owning state, projection, or presentation boundary before remediation.

The resulting shell is more honest and substantially easier to trust:

- Back navigation now unwinds monotonically instead of ping-ponging.
- Missing credentials are refused before an agent worker starts.
- The default first-value plan is context + entry points, not surprise CPG/CodeQL database construction.
- Capabilities keeps the selected action visible at every supported size.
- Review decisions produce immediate success/error receipts.
- Compact Activity, Logs, Help, Quickstart, completion, and palette surfaces retain their essential action and recovery path.
- Workspace, run, scan, and startup labels now describe the state and command that actually exist.

## Method and baseline evidence

The audit began against a fresh binary and isolated HOME/XDG/workspace state. Source was inspected only after each black-box contradiction was captured.

- Full journey baseline: `scripts/devex/artifacts/20260712-151646`
- Result: J1–J3 and J5–J17 passed their machine checks; J4 was skipped because no real OpenAI/Anthropic credential was present.
- Captures checked tmux's `alternate_on` state: the live TUI used the current pane, exited sessions recovered the saved alternate buffer, and ANSI/color checks used escape-preserving captures.
- Additional source-blind evidence was collected under `/tmp/joy3-*`, `/tmp/kuzushi-op-audit-*`, and `/tmp/kuzushi-delight-audit/`.

## Root causes and fixes

### 1. Navigation history re-added the view the operator had just left

`go_back` popped a destination, but `sync_view_change` still believed the departed view was current and pushed it back on the next redraw. `NavigationRouteState::accept_back_transition` now acknowledges the resolved destination without creating a forward step. Workbench → Config → Auth now unwinds to Config → Workbench.

### 2. Ask launched despite known-missing credentials

Ask checked a model identifier but not the existing provider-auth readiness projection. Validation now follows the documented Target → Model → Credentials order. A known-missing key returns `ask needs credentials for openai. Next: auth`, with no dispatch effect, worker, job, or running Activity.

### 3. “First result” silently selected heavyweight database work

Phase preselection treated every missing Map artifact with an available CLI as a default. Fresh Map plans now select the quick context and entry-point path. Threat-model, CPG, and CodeQL database construction remain visible opt-ins. Hunt defaults to Secrets + Semgrep; CodeQL and model-backed/deep hunts no longer become defaults merely because a binary is on PATH.

### 4. Capabilities mixed document scrolling with action-row scrolling

The overlay windowed the full Catalog document before stripping context chrome, then applied an action index as a document-line offset. At 40×12 the overlay could disappear; at 80×24 moving the cursor hid the selection. The overlay now owns a fixed summary and a cursor-windowed action list, shows one unambiguous `▸`, and renders `n/total` position feedback. The real `modules` overlay path is covered at 80×24, 60×20, and 40×12 for all three default actions.

### 5. Activity claimed full-frame chrome while idle, and split panes below viability

Frame ownership was keyed only to `ShellView::Activity`, even when no active session existed. Idle Activity now uses the standard status/footer/prompt frame and a compact responsive empty state with copyable `scan` and `run <tool>` actions. Active Activity switches to one focused pane below 70 columns and uses an outcome-first compact title so `✓ run completed` survives at 40×12.

### 6. Review decisions persisted without visible confirmation

Review commands wrote success and validation failures only to the transcript, which Workbench does not show. Decisions and suppressions now raise dismissible `DONE` receipts; invalid verdicts/reasons raise warning notices; persistence failures raise error notices. Transcript history remains intact.

### 7. Overlay backdrops preserved onboarding titles as if they were durable chrome

Capabilities now clears its complete canvas. Command Palette clears the complete origin when launched over Target, Model, Auth, or Planning onboarding, while still preserving real Workbench context for ordinary overlays.

### 8. Compact help and completion hid the means to reveal more

Prompt mode incorrectly filtered non-editing Page keys from Help and Quickstart even though PageUp/PageDown worked. Those keys remain visible while printable navigation stays Navigate-only. The misleading overflow tail is now the executable `keys more`, which opens Keymap. Completion uses a two-row compact form at 40×12 instead of silently mutating input after its seven-row popup was dropped.

### 9. Logs clipped the failure cause and recovery

Full-screen Logs emitted each transcript body as one physical line. It now word-wraps bodies after the dated prefix, makes continuation rows vertically scrollable, and preserves the actionable `Next:` suffix at 60 columns. The embedded transcript uses explicit ellipsis and only one row at the 12-row minimum.

### 10. Target and model recovery copy belonged to the wrong surface

The workspace domain error embedded CLI grammar, producing a long truncated TUI notice. Core now reports only the factual domain failure; the shell supplies concise `Next: target <existing-directory>` recovery. Targetless `next` reopens Target Picker instead of writing a hidden log. Config model selection now truthfully says to type `back`, rather than promising that the first Esc will navigate.

### 11. Workbench commands overpromised and hid primary review controls

The footer called `scan` “run scan” even though it opens the reality-derived guided plan. It now labels `scan` as `guided plan` and exposes `run sast:scan {}` as the literal rescan path. When Findings owns focus, Enter and j/k movement are ordered ahead of secondary phase/visualization controls at compact widths.

### 12. Workspace and run projections emitted contradictory or unusable state

- Bare/unsupported export now rebuilds Workspace from the active target before showing usage.
- Runs uses the already-supported eight-character `compact_run_reference`, so every displayed token can be pasted into Replay or Trace.
- Early scan cancellation fallback summaries retain `kind=scan` and `tool=sast:scan`, rather than becoming an anonymous shell job.
- Pre-TUI startup copy now directs targetless users to the picker/offline demo and explicit-target users into the operator shell.

### 13. The second audit exposed parser vocabulary instead of operator language

The natural `decision false-positive ...` was rejected because persistence uses the canonical `rejected_false_positive` value. The shell parser now accepts `false-positive`, `false_positive`, `fp`, `true-positive`, and `valid` aliases while persisting the unchanged canonical verdict. Finding detail also advertises decision, suppression, and dismissal syntax directly. `findings` now clears a pinned detail and opens the Hunt review queue, where reviewed and suppressed rows remain visibly distinct. Suppression receipts say `expires in 90 days` instead of exposing a Unix timestamp.

### 14. Targetless Capabilities looked actionable but could not act

After opting out of launch targeting, Capabilities highlighted Quick map normally. Its warning now states that Enter opens Target Picker (with `target <path>` and offline `demo` alternatives), and activation reopens the picker without loading an unrunnable command.

### 15. Decorative and truncation details damaged semantic trust

- Terrain navigation now places `Esc/q return` before optional 3D controls, so the escape path survives narrow clipping.
- Map run references render as the accepted suffix with an explicit ellipsis (`…hase-run`), rather than looking corrupt.
- The decorative Fix `掛` watermark was removed from semantic diagram whitespace after it landed inside an attack-tree connector.
- Autonomy chords now produce a visible receipt in addition to changing the posture chip.

### 16. Queue state was real but invisible during a DAG run

The Activity header only projected steer depth for taskless tools; scans with DAG rows omitted it. Queue depth is now passed independently of the live-tool projection, so a scan immediately renders `queued: 1 pending`. The audit journey asserts that state before the queued tool drains.

### 17. Audit automation and the offline handoff had their own UX debt

The journey submit helper used one Esc after F2; a notice could consume that Esc and leave Navigate mode active, turning later commands into hotkeys. It now clears a modal first, then normalizes through F2/Esc. The CLI demo now shows a representative signal-only finding, uses one `cd` followed by short `--target .` inspection commands, and ends with the explicit `kuzushi scan <repo-path>` contract.

## Validation

Final binary: `kuzushi 0.24.0-alpha.7 (775a4134f+dirty · debug)`, SHA-256 `2fd15e7525c350533b877633cf81a2c69d623ce065eccaeff832a4e0f5634f99`.

- Full final journey replay: `scripts/devex/artifacts/20260712-162248`. J1–J3 and J5–J17 reported zero machine failures; J4 was skipped for the real-credential gate.
- Final affected-journey proofs: J2 at `scripts/devex/artifacts/20260712-164628` (5 pass, 0 fail), J7 at `scripts/devex/artifacts/20260712-165713` (2 pass, 0 fail), and J9 at `scripts/devex/artifacts/20260712-165331` (4 pass, 0 fail, including `queued: 1 pending`).
- TUI library: 1,801 passed, 0 failed after the final findings-list projection and command-bar refactor.
- Core library: 2,820 passed, 0 failed.
- CLI library: 141 passed, 0 failed.
- Onboarding BDD: 7 features, 21 scenarios, 179 steps passed.
- `pnpm quality:crap-risk` passed for 197 changed code files. `pnpm check:docs`, `cargo fmt --all -- --check`, `cargo check` for TUI/CLI, and `git diff --check` all passed.

## Known external gap

The live online-agent journey still requires a real provider credential and was not faked. The missing-credential path is now explicitly covered as a refusal-before-dispatch contract; a real streaming J4 remains an external credential gate.
