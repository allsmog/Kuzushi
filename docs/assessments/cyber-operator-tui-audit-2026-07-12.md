# Cyber operator TUI experience audit — 2026-07-12

> **Historical record — superseded:** the ordered picker and Activity/
> Workbench claims below describe the assessed build before the Cockpit Spine
> cutover. The current contract lives in the terminal cockpit reference.

## Verdict

**Ready for operator use on the exercised local paths.** This second audit did
not stop at visual polish. It found and fixed state-truth, navigation,
responsive-layout, evidence-intake, and lifecycle defects that would otherwise
make the shell feel unreliable.

The current tree now gives a keyless operator an explicit Target → Model →
Credentials → Planning path, retains the consequential action and controls down
to 40×12, records cancellation as cancellation, makes every advertised document
scroll, and shows imported recon evidence with truthful execution provenance.

One coverage boundary remains explicit: J4's provider-backed bounty journey was
skipped because this audit environment had no OpenAI or Anthropic credential.
No live OAuth handshake, paid provider call, verify, or patch execution was
performed. Those unexercised external paths are not represented as green.

## Method

- Binary: `kuzushi 0.24.0-alpha.7 (775a4134f+dirty · debug)`
- Binary SHA-256:
  `d36b9a7ee5e432684a93301fd7f1b49106dbb9c405ed581b099b153f9eda1c78`
- Driver: tmux 3.6a with real keystrokes and per-checkpoint plain/ANSI captures.
- State: isolated HOME/XDG directories and fresh temporary Git targets.
- Sizes: 40×12, 60×20, 80×24, 100×30, 110×32, and 120×36.
- Profiles: xterm-256color, truecolor, high contrast, reduced motion, plain, and
  non-TTY pipe output.
- Rubric: **Honesty > Intent/State > Craft**.
- Sequence: black-box observation first, then source-level root cause, focused
  remediation, regression coverage, rebuild, and the same black-box journey
  again.

Primary evidence directories:

- `scripts/devex/artifacts/20260712-013229` — full J1–J17 sweep.
- `scripts/devex/artifacts/20260712-013845` — corrected J5/J14 rerun.
- `scripts/devex/artifacts/20260712-014037` — corrected J15 terminal matrix.
- `scripts/devex/artifacts/20260712-014056` — 80×24 planning matrix.
- `scripts/devex/artifacts/20260712-020152` — final recon intake/provenance replay.

## Findings and root-cause fixes

| Finding | Root cause | Resolution |
|---|---|---|
| Operator cancellation became `failed` | The inner SAST owner persisted every nested error as failure before the TUI could persist its cancel request; the terminal-state guard then correctly rejected the later rewrite. | SAST now classifies the shared cancellation token at its owning persistence boundary and writes `canceled` first. A real registry-path regression and an outer RunSummary/Jobs regression protect the sequence. |
| Scrolling was advertised but inert on several views | Navigation mutated one generic offset while Help/Tools/History/KB/Logs rendered route-specific offsets; other document views never applied the generic viewport at all. | Key routing now mutates the renderer-owned offset. Module, Config, Options, SAST Tasks, Runs, Replay, Trace, Context, Project Model, Strategy Queue, Workspace, Agent Chat, and Story all consume the appropriate viewport. Navigate-mode footers advertise the keys they actually accept. |
| Planning clipped confirmation and controls at common sizes | Layout choice depended mostly on width and did not compare the expanded line count with available height. The initial cursor also focused an unchecked inline action. | Planning measures rendered height and falls back to a compact, cursor-following viewport. It starts on the first selected runnable task and reserves focus detail, exact Enter outcome, and primary controls. Ultra-compact controls remain visible at 40×12. |
| Tiny onboarding and palette surfaces lost the selection or next action | Model/Auth/Target lists used fixed ranges and overlays spent scarce rows on decorative copy and uncleared backdrop content. | Pickers use height-budgeted, cursor-centered ranges. The 40×12 palette keeps query, selected match, and controls; modal bodies clear competing content while preserving context and shell chrome. |
| Keymap and option-rich pages had unreachable tails | The overlay was clipped and did not consume scroll state; Config/Options/Tasks rendered full documents without a viewport. | Keymap is scrollable and suppresses orphan headings. `j/k/g/G` and paging reach the tail, verified live at 60×20. |
| Invalid target and unavailable prerequisite refusals disappeared into the transcript | These paths logged an event without setting a visible advisory notice. | They now set persistent error/warning notices with the exact target or prerequisite, while retaining the transcript receipt. |
| Quickstart and export copy disagreed with live commands | Quickstart led with stale ordering and export errors alternated between the friendly and workspace-qualified aliases. | Quickstart follows the live target-first journey. `findings export <path> [format]` is the friendly usage, `workspace export findings` remains an explicit alias, and the shareable SARIF path is visible in the Help examples. |
| Active findings filters and durable decisions were easy to lose | Workbench refresh cleared filter context; `clear` was parsed as a literal expression; compact Confirm spent rows on diagrams before human state. | Refresh preserves active filters, `findings filter clear` resets them, and the cockpit names the active filter. Compact Confirm reserves finding identity, location, durable decision, and proof action before secondary diagrams. |
| Jobs and Activity used internal or misleading labels | Durable jobs stored the tool name but rendered only an absent phase; completed empty Activity still said it was live; small negative costs rendered `$-0.0000`. | Jobs falls back to tool identity, terminal Activity uses settled wording, next actions are human-readable, and cost is normalized to non-negative zero. |
| Common httpx JSON completed with zero imported evidence | The adapter silently skipped records without a separate `host` field even when `url` contained the host, and accepted only one status-code spelling. | The importer derives host, scheme, and port from `url`, accepts `status_code` and `status-code`, and persists imported/skipped/ignored counts. The final J6 replay shows 1 host, 1 service, and 2 notes, auto-opened in Recon Evidence. |
| Runtime-free tools claimed the configured cloud model | Run-start receipts copied `config.model` regardless of whether the descriptor/input would construct a runtime. | Shared descriptor/input-aware `tool_execution_model` logic now records only the model actually used across shell/run/scan starts. Final recon output says `execution:none · runtime-free`; explicit runtime model overrides remain preserved. |
| Compact footer overflow hid the escape hatch | A single oversized contextual binding consumed the entire footer allocation. | The first binding is width-fitted while the overflow pointer and critical escape/exit affordance remain visible. Prompt copy for Palette and Quit describes the active modal rather than a usable command prompt. |

## Black-box outcome

- Full J1–J17 sweep: J1–J3 and J5–J17 exercised; J4 skipped for missing
  provider credentials.
- J5 export rerun: **4 checks passed, 0 failed**.
- J6 recon rerun: **2 machine checks passed, 0 failed**; human inspection
  confirmed materialized host/service/note evidence and runtime-free provenance.
- J8 interruption: **6 checks passed, 0 failed**; Activity and Jobs both showed
  `canceled`, not `failed` or fabricated completion.
- J14 at 60×20 and 80×24: **19 checks passed, 0 failed** at each size.
- 40×12 stress pass: Target, Model, Auth, palette, selected planning task,
  exact Enter summary, `Space check`, `Enter run`, and `Esc` remained visible.
- J15 terminal matrix: **10 checks passed, 0 failed** across indexed color,
  high contrast, reduced motion, and truecolor.
- J17 phase reference: **30 checks passed, 0 failed**.
- Live 60×20 checks additionally proved Keymap, Options, SAST Tasks, and Config
  move from their first page to their tail with the advertised navigation keys.

## Regression and quality gates

- `cargo test -p kuzushi-core --lib --quiet`: **2,820 passed**.
- `cargo test -p kuzushi-tui --lib --quiet`: **1,782 passed**.
- `cargo test -p kuzushi-cli --quiet`: **all test binaries passed** (141 unit,
  48 + 58 + 4 + 10 + 4 integration tests).
- `cargo test -p kuzushi-bdd-tui --test onboarding --quiet`: **21 scenarios,
  177 steps passed**.
- `pnpm quality:crap-risk`: **passed for 171 changed code files**.
- `pnpm check:docs`: **passed**.
- `cargo fmt --all -- --check`: **passed**.
- `git diff --check`: **passed**.

## Remaining boundary

The 40×12 run is a deliberate stress size, not the primary composition target.
The onboarding and command-control surfaces remain usable there, but dense
post-run Workbench labels necessarily abbreviate. The supported compact
experience at 60×20 and the reference layouts at 80×24 and above are fully
exercised. Provider-backed J4 and live verify/patch still require a credentialed
follow-up environment.
