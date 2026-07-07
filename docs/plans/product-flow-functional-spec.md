# Functional spec — Kuzushi UI/UX + operator DevEX

**Status:** draft · **Branch:** `design-sync/kuzushi-tui-kit` · **Date:** 2026-07-03
**Scope:** operator-facing UX (Rust/Ratatui TUI) + operator-facing DevEX (CLI /
headless `run` / `scan`). Contributor build/SDK experience is out of scope.
**Grounding:** target-state behavior (aligned to
[`product-flow-prd.md`](./product-flow-prd.md) and
[`product-flow-design-spec.md`](../design/product-flow-design-spec.md)) with a
verified bug-fix ledger folded in (Part D).

## How to read this document

The PRD says *why*. The design spec says *how it looks and feels*. **This spec
says exactly what it does** — the testable behavioral contract an engineer builds
against and QA verifies. Every entry is a numbered **functional requirement (FR)**
with a fixed shape:

```
FR-<part><n>  <one-line title>                                    [<status>]
  Behavior:    what it does, in the present tense
  States:      the distinct states + transitions (where relevant)
  Keys/Input:  operator inputs and their effect (where relevant)
  Empty/Error: the empty-state and error-state behavior (where relevant)
  Acceptance:  the observable test that proves it
  Grounds:     PRD § · design § · current file:line · mode parity
```

**Status tags** (verified against current code 2026-07-03, see Part D):

| Tag | Meaning |
|---|---|
| `OPEN` | Verified defect or missing behavior — needs work |
| `NEW` | Target-state capability from the reframe, not yet built |
| `PARTIAL` | Partly present; spec closes the gap |
| `FIXED✓` | Already correct in current code — codified here as a **regression guard** |

Requirements are **behavior**, not look. Anything about layout, glyph choice, or
palette values defers to the design spec; this document only pins what the
behavior must be and how to test it. The three modes (scan / shell / run) obey
the [mode-parity contract](../assessments/mode-parity.md) — where a requirement is
shell-only or scan-only it says so.

---

# Part A — Cross-cutting contracts

Rules every surface obeys. If Part B and Part C disagree with Part A, Part A wins.

## A1. The signifier ↔ state ↔ intent invariant

The standing review bar for every TUI change. Three laws, each independently
testable. The current code already satisfies all three at the points the
2026-07 audit flagged (Part D); these FRs make the laws explicit so the next
change can't silently regress them.

### FR-A1.1 One glyph = one state                                        `FIXED✓`
- **Behavior:** every glyph rendered in a view maps to exactly one runtime state.
  A glyph never means different states in different views (the `●` regression —
  idle vs LIVE vs active — is resolved: Activity DAG active rows and the legend
  both use the braille spinner; `●`/`○` is reserved for the Workbench top-bar
  live/idle dot only).
- **Acceptance:** a glyph-inventory test enumerates every status glyph per view
  and asserts a single (glyph → state) mapping per view; a cross-view assertion
  forbids the same glyph denoting two different states across views without an
  explicit documented exception.
- **Grounds:** signifier invariant · `activity_dag_rows.rs:64-75,147` ·
  `render_workbench_view.rs:720-726` · shell-only.

### FR-A1.2 Every screen names what is running                          `FIXED✓`
- **Behavior:** no anonymous waiting. Every spinner is bound to a named subject.
  A counter/glyph never lies across a `running → done → failed → canceled`
  transition. A canceled task stays canceled when a late worker result arrives —
  it does not flip to `✓ done`.
- **States:** `idle → running → {done | failed | canceled}`. `canceled` and
  `failed` are terminal and absorb late results without changing glyph or label.
- **Acceptance:** snapshot test drives a task through cancel-then-late-completion
  and asserts the row stays `× canceled`; a "no anonymous spinner" test asserts
  every spinner instance carries a non-empty subject label.
- **Grounds:** signifier invariant · `activity.rs:287-295` (Canceled in the
  terminal-state guard) · shell-only.

### FR-A1.3 Every key acts or explains                                      `OPEN`
- **Behavior:** every advertised key visibly changes state, or the UI states why
  it did nothing. No advertised-but-unhandled key. No silent no-op confirm/toggle.
- **Current violation:** `y`/`n` (plan apply/discard) parse unconditionally; with
  no pending plan the handler early-returns silently with no operator feedback.
- **Target:** `y`/`n` (and every confirm alias) either act on a pending object or
  emit a one-line explanation (`nothing to apply — no plan is pending`). Keys with
  no binding in the active view are absorbed with a footer hint, never silently
  swallowed into an unrelated action.
- **Acceptance:** invoking any confirm alias with no pending object appends an
  explanation line to the transcript (asserted by test); a keybinding-coverage
  test asserts every key in the advertised footer set has a live handler in that
  view.
- **Grounds:** signifier invariant · `shell_command_specs/mod.rs:95-100,148-154`,
  `apply_or_discard.rs:66-72` · shell-only.

## A2. Interaction grammar

The largest remaining vein. Today the shell has four command grammars, view
hotkeys that fire off an empty prompt, and per-view divergence on scroll, focus,
and pause. This section defines **one** grammar. It supersedes ad-hoc per-view
bindings; the canonical table is [design spec §9](../design/product-flow-design-spec.md).

### FR-A2.1 One prompt-vs-hotkey input model                               `OPEN`
- **Behavior:** typing text always builds the command-prompt buffer. View hotkeys
  never intercept a plain alphanumeric keystroke meant for the prompt.
- **Current violation:** there is no prompt-focus mode; when the prompt is empty
  the first keystroke routes to view hotkeys, so typing `config` fires the `c`
  hotkey (`exploit-chain:scan`) then inserts `onfig`. No mode hint; no advertised
  escape.
- **Target model:** hotkeys are reachable only in an explicit, **visibly
  indicated** command/navigation mode, or require a modifier; plain keystrokes
  always append to the prompt. The mode indicator and the toggle key are shown in
  the footer at all times. Whichever concrete model design §9 lands on, the
  invariant is: **no plain letter both types into the prompt and fires a hotkey
  depending on buffer emptiness.**
- **Keys/Input:** the mode toggle is a single advertised key; `Esc` always
  returns to prompt-text entry from any mode.
- **Acceptance:** a key-sequence test types `c`,`o`,`n`,`f`,`i`,`g`,`Enter` from a
  cleared prompt in Workbench and asserts the `config` command ran and
  `exploit-chain:scan` did **not** dispatch.
- **Grounds:** PRD §12.10 · design §9 · `key_dispatch.rs:23-27`,
  `cursor_and_view_keys.rs:12-36`, `view_keybinding_groups.rs` · shell-only.

### FR-A2.2 Canonical key-semantics table                                   `OPEN`
- **Behavior:** one binding per concept, identical across every view that
  supports the concept. The table:

  | Concept | Binding | Rule |
  |---|---|---|
  | Scroll line | `j`/`k` and `↑`/`↓` | Arrows scroll **content** in scrollable views; they recall command history **only** when the prompt has focus/content |
  | Scroll page | `PgUp`/`PgDn` | Same in every scrollable view |
  | Scroll ends | `g`/`G` | `g`=top, `G`=bottom, **everywhere**; reserved — no view may repurpose `g` |
  | Next / prev focus | `Tab` / `Shift+Tab` | `Tab`=next pane, `Shift+Tab`=**previous** pane (a true reverse, not a re-toggle) in every multi-pane view |
  | Confirm / reject | `y` / `n` | Act on a pending object or explain (FR-A1.3) |

- **Current violations:** `↑`/`↓` recall history in *every* view (never scroll);
  `Shift+Tab` reverses in Workbench but re-toggles in Activity/Planning; `g` is
  scroll-to-top everywhere **except** PlanningPicker where it toggles
  rebuild-cached. Target: PlanningPicker's rebuild toggle moves off `g` (e.g. `r`).
- **Acceptance:** per-concept tests: arrows scroll content in Logs/Help and only
  recall history when the prompt is non-empty; `Shift+Tab` in Activity lands on
  the previous pane, not the same one it started from after two presses; `g` in
  PlanningPicker scrolls to top and the rebuild toggle responds to its new key.
- **Grounds:** design §9 · `cursor_and_view_keys.rs:119-133`,
  `scroll_navigation.rs:34-41`, `view_keybinding_groups.rs:113-118`,
  `picker_keys.rs:536-548` · shell-only.

### FR-A2.3 One scroll/focus-on-re-entry rule                               `OPEN`
- **Behavior:** re-entering any scrollable view restores its last scroll position
  and focus. The rule is uniform — there is no set of views that snap to top while
  others restore.
- **Current violation:** Logs/Workbench/Activity restore prior scroll; Default-
  target views (`Help`/`Tools`/`Health`/…) zero their offset on view change.
- **Target:** every view persists its own scroll+focus and restores on re-entry;
  an explicit `g` (scroll-to-top) is the only way to jump to top.
- **Acceptance:** a navigation test scrolls Help down, leaves, returns, and asserts
  the offset is preserved; repeats for a former snap-to-top view.
- **Grounds:** `log_and_scroll.rs:120-143`, `handle_command.rs:121,228,279` ·
  shell-only.

### FR-A2.4 Activity pause semantics are distinct and advertised            `OPEN`
- **Behavior:** the three pause concepts in Activity are separated, each with a
  distinct advertised key and an unambiguous label:

  | Concept | Effect | Advertised as |
  |---|---|---|
  | Feed freeze | stop scrolling the event feed; work continues | `Space feed freeze` |
  | Scan pause | actually pause the running scan | `p pause scan` |
  | Auto-tail freeze | manual scroll stops auto-tail; `G`/`p`-resume re-arms | shown as a `tail off` state chip |

- **Current state:** all three exist; `p` is now advertised in the footer during a
  scan (improved), but `Space` (least consequential) and `p` still read as similar
  "pause" without disambiguation, and auto-tail freeze is implicit.
- **Acceptance:** footer during a live scan shows all three affordances with the
  labels above; a test asserts `Space` does not pause the scan and `p` does.
- **Grounds:** `view_keybinding_groups.rs:20-25`, `log_and_scroll.rs:64-76`,
  `activity.rs:505-527` · shell-only.

### FR-A2.5 Per-task cancel in Activity                                      `OPEN`
- **Behavior:** with a task focused in Activity, a cancel key cancels **that
  task**; a separate global cancel cancels all active work. Per-task cancel joins
  the existing per-task `Enter`/`f`/`o`.
- **Current state:** only global `cancel`/`c`/`stop` exists (cancels all).
- **Keys/Input:** focused-task cancel is a distinct advertised key; it arms then
  confirms (consistent with the two-stage global cancel — do-not-cut, FR-D).
- **Acceptance:** focusing task B and issuing per-task cancel cancels B while task
  A keeps running (asserted by state test).
- **Grounds:** `activity.rs:527` (`mark_active_tasks_canceled`) ·
  `view_keybinding_groups.rs:29-44` · shell-only.

## A3. Terminal robustness

The shell must render correctly on the terminals operators actually use —
notably macOS Terminal.app (the platform is Darwin), which is not truecolor.

### FR-A3.1 Color capability detection + downsample                         `OPEN`
- **Behavior:** the theme detects terminal color depth (`COLORTERM`/`TERM`) and
  renders in the richest supported mode: truecolor → 256 → 16. Semantic tones stay
  distinguishable at every depth. `NO_COLOR` collapses to modifier-only styling
  (already respected). `KUZUSHI_THEME=high-contrast` and `KUZUSHI_REDUCED_MOTION`
  remain honored at the adapter boundary.
- **Current violation:** all tones are hard-coded `Color::Rgb`; no capability
  detection or downsample path, so tones collapse on non-truecolor terminals.
- **Acceptance:** a theme test resolves each semantic tone under truecolor / 256 /
  16 and asserts (a) the mapping is total and (b) no two semantic roles collapse to
  the same 16-color slot. Env detection reads through the config/adapter boundary,
  not `std::env` in theme code (operator-control-surfaces contract).
- **Grounds:** PRD §12.10 · design §12 · `theme/mod.rs:12-28`,
  `theme/config.rs:32-38` · shell-only.

### FR-A3.2 Unicode-width–correct layout                                    `OPEN`
- **Behavior:** all display-width math uses grapheme display width, not char
  count. Wide glyphs (CJK, the phase kanji 組/崩/作/掛, emoji) count as 2 cells;
  tables, panes, and the footer align and do not spill.
- **Current violation:** width math is 1-cell-per-char via `.chars().count()` in
  `fit`/`pad`/column-width helpers; no `unicode-width` dependency in the crates.
- **Acceptance:** a layout test pads/fits strings containing kanji and emoji and
  asserts the rendered cell width equals the target width; a Workbench snapshot
  with a CJK finding title keeps column borders aligned.
- **Grounds:** design §12 · `renderer/shared/text/mod.rs:22,211`,
  `panes.rs:116-118`, `model_picker.rs:32-40` · shell-only.

### FR-A3.3 Every frame-rendered surface has a plain fallback              `PARTIAL`
- **Behavior:** no surface is TTY-only without a text equivalent. Frame-rendered
  pages (3D terrain, box-drawing DFD/attack-tree) degrade to `scene_page_lines`;
  the terrain heatmap has a text projection from the same data.
- **Current state:** line pages and box diagrams degrade; the 3D terrain shows a
  "renders in a TTY" note but its underlying heatmap data has a text form —
  wire the plain path to that data rather than a bare note.
- **Acceptance:** rendering every `VizPage` in non-TTY mode yields non-empty,
  ANSI-free, box-drawing-free text (asserted per page).
- **Grounds:** mode-parity · `renderer/views/scene/` · shell-only (viz is
  interactive), plain output required.

---

# Part B — Surface-by-surface behavior

One subsection per operator-facing surface. Each pins behavior, states, keys,
empty/error states, and acceptance. Look-and-feel defers to the design spec.

## B1. Cockpit / Workbench — the default landing surface

### FR-B1.1 Pane layout, focus, and honest focus signifier               `FIXED✓`
- **Behavior:** wide terminals render `[SOURCE | CENTER (CODE/DFD) | FINDINGS |
  DETAILS]`; compact terminals collapse toward the review path. `Tab` cycles pane
  focus, `Shift+Tab` reverses, `j`/`k` move the focused pane, `Enter` pins/opens
  the focused finding. The focus signifier reflects **actual** focus on every page
  (not hardcoded on non-Review pages).
- **Acceptance:** a render test on the Terrain/Ship page asserts the focus ring is
  drawn only on the truly focused pane (regression guard for the former hardcoded
  `focused=true`).
- **Grounds:** PRD §18 · design §2 · `render_workbench_view.rs:234-250`,
  `app.workbench_focus` · shell-only.

### FR-B1.2 LIVE lights only on real run activity                         `FIXED✓`
- **Behavior:** the top-bar `LIVE` indicator lights iff there is real run activity
  (`has_run_activity`); it is dark otherwise.
- **Acceptance:** state test asserts `LIVE` dark with no active tool and lit during
  a running tool.
- **Grounds:** design §2 · `render_workbench_view.rs:720-726` · shell-only.

### FR-B1.3 Phase chip/rail derive from workspace reality, target-gated   `FIXED✓`
- **Behavior:** the phase chip (`組 map 1/4`) and rail derive the current phase
  from `journey.rs` (map artifacts on disk, findings, triage/verify state), **not**
  from the viewed page. With no active target, no phase chrome renders at all. The
  viewed page is a separate `page:` span.
- **States:** phase ∈ {組 map, 崩 hunt, 作 confirm, 掛 fix}; never two `▸ current`
  markers; never regresses a Done phase to Current when the operator opens a page.
- **Acceptance:** (a) `top_bar_omits_journey_chrome_without_a_target`; (b) opening
  the Terrain page with findings present still shows `作 confirm` from reality, not
  the page.
- **Grounds:** design §2 · `ui_view_models/workbench.rs:253-261`,
  `journey.rs:98-122,219-237` · shell-only, target-gated.

### FR-B1.4 Findings list carries the confirmed-vs-guess marker           `FIXED✓`
- **Behavior:** every findings-LIST row shows a per-row proof marker
  (`✓ runtime · ◇ reviewed/static · ? guess · ! rejected`) with verdict +
  confidence, and a legend line above the list. Untriaged rows read `?`, never
  blank. The marker updates live as verification completes.
- **Acceptance:** list snapshot asserts a proof marker column on every row and the
  legend line; a state test flips a finding to confirmed and asserts the row marker
  changes to `✓`.
- **Grounds:** PRD §12.6, §13 · design §2 · `panes.rs:802-858`,
  `ui_view_models/findings.rs:71-72` · shell + plain.

### FR-B1.5 Empty states are actionable and offline-aware                   `OPEN`
- **Behavior:** every Workbench pane empty-state names the next concrete action,
  including the keyless/offline path. With no target: point to target selection.
  With a target but no findings: point to `scan`/`next`/`demo`. Copy is single-
  sourced (no 12× copy-pasted "needs an active workspace" drift).
- **Acceptance:** empty-state snapshots for {no target, target-no-findings} include
  an offline-reachable action; a grep test asserts the workspace-required copy has
  one canonical definition.
- **Grounds:** journey audit · design §10 · `panes.rs`, `run_shell.rs:85-90` ·
  shell-only.

## B2. Aim (組) — map the target, build the engagement folder

### FR-B2.1 Aim seeds a mutable harness and previews engine cost            `NEW`
- **Behavior:** entering Aim maps the target and materializes
  `engagement/harness.toml` (the mutable scan unit). The Aim surface shows the
  harness seed (recon signals, deterministic seeds) and an engine-prep row where
  each analysis engine shows its enablement + cost estimate before commit.
- **States:** harness ∈ {unseeded, seeded, edited}; each engine ∈ {off, on(+cost)}.
- **Empty/Error:** no target → Aim is unavailable and says so (target-gated).
- **Acceptance:** completing Aim writes `engagement/harness.toml`; the engine row
  renders a cost estimate for each heavyweight engine (cpg/codeql) before it is on.
- **Grounds:** PRD §7, §12.2, §12.4 · design §3 · `EngineChips` component ·
  all modes seed the harness; the interactive prep row is shell-only.

## B3. Hunt (崩) — signal-driven proposal queue

### FR-B3.1 Priced, budget-gated proposal queue                             `NEW`
- **Behavior:** signal generators (commit-archaeology, threat-model, dep-intel, …)
  emit hunt proposals. Each `ProposalRow` shows `id · title · generator · $price ·
  yield`; the operator keeps (`k`) or skips (`s`) before firing. A budget meter
  shows spend against cap; proposals that would exceed the cap are gated.
- **States:** proposal ∈ {proposed, kept, skipped}; queue total price ≤ budget cap.
- **Keys/Input:** `k` keep, `s` skip, `j`/`k`(nav per A2 — cursor via arrows/jk
  per canonical table), fire the kept set as a **sweep** (`focus × strategy ×
  model × runs`).
- **Empty/Error:** no signals yet → empty state points to Aim/recon.
- **Acceptance:** keeping two of three proposals and firing runs exactly the kept
  set; a proposal exceeding remaining budget renders gated and cannot be fired.
- **Grounds:** PRD §12.1–12.3 · design §4 · `ProposalRow`/`MeterBar` components ·
  scan+shell (sweep runs headless too).

## B4. Confirm (作) — proof, configurably

### FR-B4.1 Verifier strategy and corroboration are configurable            `PARTIAL`
- **Behavior:** the Confirm surface exposes the adversarial verifier (guilty-
  until-proven) and its corroboration threshold. Findings carry proof state
  ✓/◇/?/! (FR-B1.4); the operator can require N-way corroboration before a finding
  is promoted to confirmed.
- **States:** finding proof ∈ {confirmed ✓, candidate ◇, unverified ?, rejected !};
  `corroboration_count` tracked per finding.
- **Acceptance:** setting corroboration threshold to 2 keeps a single-vote finding
  at `◇ candidate` until a second independent pass agrees.
- **Grounds:** PRD §12.6, §13 · design §5 ·
  `findings/persistence/open/triage_and_verification.rs` · scan+shell+run.

### FR-B4.2 Manual false-positive marking is first-class                     `PARTIAL`
- **Behavior:** the operator can mark a finding a false positive from the list/
  detail; the mark is sticky (`triaged_by=human`) and survives re-runs and dedup.
- **Acceptance:** marking a finding FP, then re-running the producing tool, leaves
  it FP (not resurrected as untriaged).
- **Grounds:** PRD §12.6 · `findings/persistence/open/finding_writes.rs` ·
  scan+shell+run.

## B5. Fix (掛) & Report

### FR-B5.1 Patch view shows rationale, diff, tests, guardrail              `PARTIAL`
- **Behavior:** `/patch <alias>` opens a view with RATIONALE / DIFF / TESTS /
  GUARDRAIL sections for the finding's fix. The patch is presented dry-run by
  default; applying it is an explicit operator action.
- **Acceptance:** opening `/patch <alias>` renders all four sections; no file is
  written until the operator confirms apply.
- **Grounds:** PRD §12 · design §6 · `ShellView::Patch(String)` · shell-only view
  over shared artifacts.

### FR-B5.2 Report/export produces a human bundle                           `PARTIAL`
- **Behavior:** Report emits the engagement findings as a shareable artifact:
  `format ∈ {json, jsonl, sarif, csv, markdown-bundle}`. The markdown bundle is a
  directory (README from `build_pr_comment`, per-finding files, manifest).
- **Acceptance:** exporting `markdown-bundle` to a dir produces README + per-finding
  files + manifest; SARIF emits one `runs[]` per `Finding.tool`. (CLI parity:
  FR-C5.)
- **Grounds:** PRD §12 · design §6 · `workspace:export-findings` · all modes.

## B6. The steering gate (phase-boundary overlay)

### FR-B6.1 Steering gate composes the next sweep before it fires           `NEW`
- **Behavior:** at each phase boundary an overlay lets the operator steer the next
  sweep: engines row (per-scan enablement + cost), harness row (edit seeds/scope),
  focus row (typed intent), tiers row (model tier per role + cost). Firing runs the
  composed sweep; the overlay is the single place non-determinism spend is decided.
- **Acceptance:** editing the focus row to `focus on sqli` re-ranks the proposal
  set toward SQLi CWEs and seeds; the composed engine/tier selection is what the
  sweep executes.
- **Grounds:** PRD §5.1, §10, §12 · design §8 · `EngineChips`/`MeterBar` · sweep
  runs in scan+run; the overlay is shell-only.

### FR-B6.2 "Focus on X" is typed-intent steering, not free text           `NEW`
- **Behavior:** operator focus input is parsed to typed intent (target CWE class,
  oracle selection, seed re-rank), not a raw prompt string. The gate shows the
  resolved intent (`focus: SQLi → CWE-89, taint oracles on, sqli seeds ↑`) so the
  operator sees what the words did.
- **Empty/Error:** unrecognized focus → the gate says it couldn't map the intent
  and leaves ranking unchanged (honest, not silent).
- **Acceptance:** `focus on sqli` resolves to the SQLi CWE set (asserted); an
  unmappable focus term renders the "couldn't map" state and does not silently
  reorder.
- **Grounds:** PRD §5.1, §12 · design §8 · options-not-env (focus flows through a
  declared option/intent, not an env var) · scan+shell+run.

## B7. Activity view

### FR-B7.1 Live feed, DAG rows, and truthful legend                      `FIXED✓`
- **Behavior:** a split-pane dashboard: DAG status + ACTIONS strip left, OUTPUT
  deck right. Feed rows come from `trace.step(...).emit()`. The DAG legend matches
  the glyphs rows actually draw (active = braille spinner, per FR-A1.1). Hidden
  modules collapse into one `subsystems` row unless `V` verbose is on.
- **Keys/Input:** `j`/`k`/`g`/`G` scroll focused pane; `Tab` focus; `←`/`→` output
  pages; `V` verbose; pause per FR-A2.4; per-task cancel per FR-A2.5; `Enter`
  focus task, `o` open artifact, `f` findings.
- **Acceptance:** legend glyphs equal rendered active-row glyphs (regression guard);
  hidden-module events stay out of the feed until `V`.
- **Grounds:** design §2 · `activity_dag_rows.rs:64-147` · shell-only; producers
  emit trace in all modes.

## B8. Findings / Finding

### FR-B8.1 List and detail share the proof vocabulary                    `FIXED✓`
- **Behavior:** the list (FR-B1.4) and the detail pane use the same proof markers
  and legend. The detail empty-state reads "no finding selected — move through
  FINDINGS to preview" (not a false "press Enter"); the detail previews the cursor
  finding before Enter.
- **Acceptance:** detail empty-state copy matches; previewing does not require Enter.
- **Grounds:** journey audit corrections · `detail_pane.rs`, `panes.rs` · shell+plain.

### FR-B8.2 Alias drill and cross-run identity are stable                  `PARTIAL`
- **Behavior:** a finding's alias is stable across runs; `open <alias>` and the
  alias drill resolve to the same finding after re-scan/dedup. Engagement-scoped
  merge unions findings across runs without clobbering triage.
- **Acceptance:** re-scanning yields the same alias for an unchanged finding; a
  second run's new finding appears without dropping the first run's triaged ones.
- **Grounds:** PRD §12 (cross-run merge = New) · `findings/persistence/` ·
  scan+shell+run.

## B9. Threat views

### FR-B9.1 DFD / attack-tree / chain views regenerate on a hotkey         `PARTIAL`
- **Behavior:** the threat surfaces (DFD data-flow graph, attack tree, exploit
  chain) render from persisted artifacts and expose a regenerate hotkey that re-
  runs the producing tool and refreshes the view. Each has an `empty_hint` when the
  backing artifact is absent — never dummy content.
- **Acceptance:** a page with no artifact draws exactly its guidance line; the
  regenerate hotkey dispatches the mapped tool and the view updates on completion.
- **Grounds:** PRD §12.8 · design §7, mode-parity viz notes · `renderer/views/scene/`
  · shell-only.

## B10. Catalog / Tools — discoverability

### FR-B10.1 Tools are grouped by phase, not a flat wall                   `FIXED✓`
- **Behavior:** `/tools` groups tools under phase headers MAP / HUNT / CONFIRM /
  FIX / OPERATE with per-group hints; module detail uses the human `name` field.
- **Acceptance:** `/tools` output contains the five group headers and no
  ungrouped tail (asserted on `tools_lines`).
- **Grounds:** journey/devex audits · `tools_lines.rs:78-92`, `tools.rs:188-214` ·
  shell-only.

### FR-B10.2 Completion is discoverable and its preview is wired            `OPEN`
- **Behavior:** tab-completion shows a rendered popup (`Tab cycles · Enter selects
  · Esc restores`) and an inline ghost-text preview of the top completion as the
  operator types.
- **Current violation:** the popup renders, but `completion_preview()` ghost-text
  is tested and never drawn — dead code. Target: wire it into the renderer (draw
  the ghost suffix in `subtle` tone) or remove it. This spec chooses **wire it**.
- **Acceptance:** typing a tool prefix renders the ghost suffix inline; a renderer
  test asserts the preview string appears in the drawn buffer (kills the dead-code
  gap).
- **Grounds:** devex audit · `line_editor/.../completion_cycle.rs:76`,
  `chrome/completion_popup.rs:73`, `app/tests.rs:5810-5827` · shell-only.

---

# Part C — DevEX / headless contract

The operator experience outside the TUI: CLI flags, `run`/`scan` machine output,
first-run, discoverability. Headless behavior must be scriptable and CI-safe.

### FR-C1 `--target` resolves by one rule across every subcommand           `OPEN`
- **Behavior:** target resolution is single-sourced. The global `--target` flag is
  the canonical input; subcommands do not redefine it with divergent (blank) help;
  `scan`'s positional `[TARGET]` and the global flag reconcile to the same resolved
  target. Every subcommand's `--help` documents target identically.
- **Current state:** the specific blocker is fixed (`kuzushi --target . scan`
  succeeds; scan positional is `Option`), but `--target` still appears in three
  shapes and the `runs`/`shell` per-subcommand redefinitions have blank help.
- **Acceptance:** a CLI test asserts `--target`/`[TARGET]` help text is non-empty
  and identical in wording across `scan`, `shell`, `findings`, `finding`, `runs *`;
  `kuzushi --target . scan` and `kuzushi scan .` resolve to the same target.
- **Grounds:** journey/devex audits · `cli/mod.rs:11-13`, `command.rs:15-22`,
  `dispatch/mod.rs:71-78`, `subcommands.rs:59-95` · CLI (all modes consume the
  resolved target).

### FR-C2 `run` emits a JSON envelope on every outcome                     `FIXED✓`
- **Behavior:** `kuzushi run <tool>` prints a single JSON envelope to stdout on
  success, prepare-failure, and execution-failure alike — never empty stdout.
  Envelope carries `{ok, status, ...errors}`. This is the CI/`jq` contract.
- **Acceptance:** a test pipes each outcome through `jq` and asserts a parseable
  object; a prepare-error (bad option) yields `{ok:false,status:"failed",...}` on
  stdout, not empty.
- **Grounds:** mode-parity · `application/run_tool.rs:27-67,140-149` · run-only
  (scan uses `--ci`; shell is interactive).

### FR-C3 Every CLI arg has help text                                        `OPEN`
- **Behavior:** no clap flag or positional ships with empty help. This includes the
  ~19 currently-blank args (16 in `runs` subcommands: `--target`/`--json`/
  `<RUN_ID>`/`<BASE_RUN_ID>`/`<COMPARE_RUN_ID>`; plus `shell --target`,
  `demo --json`, `config init --force`, `mcp health <backend>`).
- **Acceptance:** a test walks the clap command tree and asserts every arg has a
  non-empty `about`/help; fails the build if any is blank.
- **Grounds:** devex audit · `subcommands.rs:50-106`, `command.rs:16,163` · CLI.

### FR-C4 `--input` accepts inline JSON, `@file`, and stdin                 `FIXED✓`
- **Behavior:** `run --input` resolves `-` → stdin, `@path` → file, else inline
  JSON. The flag help documents all three.
- **Acceptance:** the three forms produce identical dispatch for equal payloads
  (asserted); help text mentions `@path` and `-`.
- **Grounds:** devex audit · `application/run_tool.rs:46-56`, `command.rs:170` ·
  run-only.

### FR-C5 First-class `kuzushi export` subcommand                            `OPEN`
- **Behavior:** a top-level `kuzushi export --format <f> --out <path> --target <t>`
  subcommand wraps `workspace:export-findings`; `--format markdown-bundle` writes a
  directory. It is discoverable in `kuzushi --help` alongside `scan`/`findings`.
- **Current state:** export is reachable only via `run workspace:export-findings`
  or `scan --sarif`; no first-class subcommand.
- **Acceptance:** `kuzushi --help` lists `export`; `kuzushi export --format
  markdown-bundle --out DIR` produces the bundle; every `format` value round-trips.
- **Grounds:** journey audit · `command.rs:11-184`,
  `modules/workspace_tools/mod.rs:30` · CLI (sugar over the shared tool).

### FR-C6 Every advertised tool is dispatchable (coverage)                 `FIXED✓`
- **Behavior:** every tool declared in a module descriptor resolves to a live
  executor in the dispatch match — no advertised-but-unreachable tool (the
  `recon:import` BLOCKER is resolved: declared in `recon_module.rs` and wired in
  the dispatch arm).
- **Acceptance:** a registry test enumerates all descriptor tool names and asserts
  each dispatches to an executor (not "unknown tool"). This guards the whole
  `<moduleId>:<action>` surface, not just recon.
- **Grounds:** devex audit · `run_taint_iris_tool.rs:193`, `recon_module.rs:19,67-79`,
  `capabilities/recon/adapters/tool.rs:66` · all modes.

### FR-C7 Keyless/offline first-run reaches a real result                  `FIXED✓`
- **Behavior:** a first-run operator with no API key, no model, and no external
  scanners can reach a deterministic result. Shell `demo` runs the same
  `secret-scan + iac-scan` deterministic task list as `kuzushi demo` (no model/key
  required); the model picker surfaces an offline "demo" entry; empty states point
  to `demo`.
- **Acceptance:** in a keyless env, shell `demo` produces findings via the manual
  deterministic task list (asserted equal to `cli/application/demo.rs` input); the
  model picker renders the offline entry.
- **Grounds:** journey/devex audits · `scan_startup.rs:74`, `demo.rs:36`,
  `model_picker.rs:17,79-87`, `recommendation.rs:162-181` · CLI+shell.

### FR-C8 doctor + preflight validate model↔backend before any API call     `OPEN`
- **Behavior:** an incompatible model/backend pair (e.g. `anthropic:` model +
  codex/openai backend) is rejected up front by `doctor` and by a pre-run preflight
  with an actionable message — before the first API call — consistent with the
  no-silent-fallback policy (this is a hard error, not a fallback).
- **Current violation:** `validate_model_api_key_env` checks syntax/provider-set/
  key-present only; it never cross-validates provider against the configured
  backend, so the pair fails only at API-call time.
- **Acceptance:** `doctor` on an incompatible pair returns FAIL with a `Next:`
  remediation naming both the model and the backend; a pre-run preflight refuses to
  start and prints the same message; a compatible pair passes.
- **Grounds:** journey audit · model/runtime safety (no silent fallback) ·
  `runtime/policy/no_silent_fallback.rs:12-17`, `doctor/checks.rs:281` · CLI+shell+run.

### FR-C9 First-run orientation is not inert                                 `OPEN`
- **Behavior:** on true first-run (target set, no prior run) the shell proactively
  orients the operator — the recommender/journey surface presents a concrete first
  action rather than an empty artifact state that only fills after a manual run.
- **Current violation:** `/recommend` reads a persisted `recommendations.json`;
  with a target but no run it shows an empty state until a `recommend` run
  completes — inert on first contact.
- **Acceptance:** first-run with a fresh target renders a non-empty first-action
  recommendation (from a synchronous cheap heuristic or an auto-triggered refresh
  whose pending state is named, not blank).
- **Grounds:** journey audit · `ui_view_models/recommendation.rs:60-106,183-199` ·
  shell-only (CLI `doctor`/`demo` cover the headless first-run).

---

# Part D — Verified bug-fix ledger

Every claim from the 2026-07 audits, re-verified against current code on
2026-07-03 (four read-only passes). `OPEN`/`CHANGED` items are governed by an FR
above; `FIXED✓` items are codified as regression guards so they can't silently
regress.

### D.1 Still open — governed by an FR

| # | Defect | Verdict | Current site | FR |
|---|---|---|---|---|
| 1 | Empty-prompt hotkey trap (typing `config` fires `c`) | CONFIRMED | `key_dispatch.rs:23-27`, `cursor_and_view_keys.rs:12-36` | FR-A2.1 |
| 2 | `↑`/`↓` recall history in every view, never scroll | CONFIRMED | `cursor_and_view_keys.rs:119-133` | FR-A2.2 |
| 3 | `Shift+Tab` reverses in Workbench, re-toggles elsewhere | CONFIRMED | `view_keybinding_groups.rs:113-118`, `picker_keys.rs:544-548` | FR-A2.2 |
| 4 | `g` = scroll-top everywhere but rebuild-toggle in PlanningPicker | CONFIRMED | `scroll_navigation.rs:37`, `picker_keys.rs:536-539` | FR-A2.2 |
| 5 | Three pause semantics; auto-tail freeze implicit | CHANGED | `view_keybinding_groups.rs:20-25`, `log_and_scroll.rs:64-76` | FR-A2.4 |
| 6 | No per-task cancel in Activity | CONFIRMED | `activity.rs:527` | FR-A2.5 |
| 7 | Scroll-on-re-entry inconsistent | CONFIRMED | `log_and_scroll.rs:120-143` | FR-A2.3 |
| 8 | `y`/`n` parse unconditionally → silent no-op | CONFIRMED | `shell_command_specs/mod.rs:95-100`, `apply_or_discard.rs:66-72` | FR-A1.3 |
| 9 | Truecolor-only palette, no downsample | CONFIRMED | `theme/mod.rs:12-28` | FR-A3.1 |
| 10 | No unicode-width; 1-cell-per-char | CONFIRMED | `renderer/shared/text/mod.rs:22,211` | FR-A3.2 |
| 11 | Model↔backend not validated up front | CONFIRMED | `no_silent_fallback.rs:12-17`, `doctor/checks.rs:281` | FR-C8 |
| 12 | Module-recommender inert on first-run | CONFIRMED | `recommendation.rs:60-106` | FR-C9 |
| 13 | `--target` 3 shapes + blank per-subcmd help | CHANGED | `cli/mod.rs:11-13`, `subcommands.rs:59-95` | FR-C1 |
| 14 | ~19 blank `--help` args (16 in `runs`) | CHANGED | `subcommands.rs:50-106`, `command.rs:16,163` | FR-C3 |
| 15 | No first-class `export` subcommand | CONFIRMED | `command.rs:11-184` | FR-C5 |
| 16 | `completion_preview()` ghost-text = dead code | CONFIRMED | `completion_cycle.rs:76`, `app/tests.rs:5810-5827` | FR-B10.2 |

### D.2 Fixed since the audit — codified as regression guards

| # | Former defect | Verdict | Current site | Guard FR |
|---|---|---|---|---|
| 17 | Canceled task flips to `✓ done` on late result | FIXED | `activity.rs:287-295` | FR-A1.2 |
| 18 | Workbench fabricates phase chip with no target | FIXED | `workbench.rs:253-261`, `journey.rs:121-122` | FR-B1.3 |
| 19 | Phase chip tracks viewed page, double `▸` | FIXED | `journey.rs:98-111,219-237` | FR-B1.3 |
| 20 | Focus signifier hardcoded `focused=true` | FIXED | `render_workbench_view.rs:234-250` | FR-B1.1 |
| 21 | DAG legend `● active` lie | FIXED | `activity_dag_rows.rs:64-75,147` | FR-A1.1, FR-B7.1 |
| 22 | `recon:import` unreachable (BLOCKER) | FIXED | `run_taint_iris_tool.rs:193`, `recon_module.rs:19` | FR-C6 |
| 23 | `run` prepare-errors emit empty stdout | FIXED | `application/run_tool.rs:34-40` | FR-C2 |
| 24 | `--input` inline-only | FIXED | `application/run_tool.rs:46-56` | FR-C4 |
| 25 | `demo` invisible in shell / not deterministic | FIXED | `scan_startup.rs:74`, `demo.rs:36` | FR-C7 |
| 26 | Model picker paid-only | FIXED | `model_picker.rs:17,79-87` | FR-C7 |
| 27 | Findings list has no proof marker (detail-only) | FIXED | `panes.rs:802-858` | FR-B1.4 |
| 28 | `/tools` flat alphabetical wall | FIXED | `tools_lines.rs:78-92`, `tools.rs:188-214` | FR-B10.1 |

### D.3 Do-not-cut (verified strengths to preserve)

Two-stage Ctrl+C cancel (honest, consistent); no anonymous spinner; `journey.rs`
refuses to forge Done; `doctor` WARN/FAIL always names problem + `Next:`
remediation; scan `--fail-on` exits 3 (CI-safe, distinct from 1/2); in-session
API-key paste; `NO_COLOR` respected through every theme fn; out-of-scope refusal
names file + edit; option validation enumerates valid keys/enums. Any change that
regresses one of these fails review.

---

# Part E — Traceability matrix

FR → PRD § → design § → status → mode parity. (File:line grounding lives on each
FR and in Part D.)

| FR | Title | PRD § | Design § | Status | Modes |
|---|---|---|---|---|---|
| A1.1 | One glyph = one state | §13 | §2 | FIXED✓ | shell |
| A1.2 | Every screen names what's running | §13 | §2 | FIXED✓ | shell |
| A1.3 | Every key acts or explains | §13 | §9 | OPEN | shell |
| A2.1 | One prompt-vs-hotkey model | §12.10 | §9 | OPEN | shell |
| A2.2 | Canonical key-semantics table | §12.10 | §9 | OPEN | shell |
| A2.3 | One scroll/focus re-entry rule | §12.10 | §9 | OPEN | shell |
| A2.4 | Activity pause semantics distinct | §12.10 | §9 | OPEN | shell |
| A2.5 | Per-task cancel in Activity | §12.10 | §9 | OPEN | shell |
| A3.1 | Color detection + downsample | §12.10 | §12 | OPEN | shell |
| A3.2 | Unicode-width layout | §12.10 | §12 | OPEN | shell |
| A3.3 | Plain fallback per surface | — | §11,§12 | PARTIAL | shell+plain |
| B1.1 | Pane focus + honest signifier | §18 | §2 | FIXED✓ | shell |
| B1.2 | LIVE on real activity only | — | §2 | FIXED✓ | shell |
| B1.3 | Phase chip from reality, gated | — | §2 | FIXED✓ | shell |
| B1.4 | List proof marker | §12.6,§13 | §2 | FIXED✓ | shell+plain |
| B1.5 | Actionable offline-aware empties | — | §10 | OPEN | shell |
| B2.1 | Aim seeds harness + engine cost | §7,§12.2,§12.4 | §3 | NEW | all |
| B3.1 | Priced proposal queue | §12.1–3 | §4 | NEW | scan+shell |
| B4.1 | Configurable verifier/corroboration | §12.6,§13 | §5 | PARTIAL | all |
| B4.2 | Manual FP marking sticky | §12.6 | §5 | PARTIAL | all |
| B5.1 | Patch view 4 sections | §12 | §6 | PARTIAL | shell |
| B5.2 | Human export bundle | §12 | §6 | PARTIAL | all |
| B6.1 | Steering gate composes sweep | §5.1,§10,§12 | §8 | NEW | scan+shell |
| B6.2 | Focus = typed intent | §5.1,§12 | §8 | NEW | all |
| B7.1 | Activity feed + truthful legend | — | §2 | FIXED✓ | shell |
| B8.1 | List/detail share proof vocab | §13 | §2 | FIXED✓ | shell+plain |
| B8.2 | Stable alias + cross-run merge | §12 | §2 | PARTIAL | all |
| B9.1 | Threat views regenerate | §12.8 | §7 | PARTIAL | shell |
| B10.1 | Tools grouped by phase | — | §7 | FIXED✓ | shell |
| B10.2 | Completion preview wired | — | §9 | OPEN | shell |
| C1 | One `--target` rule | — | §11 | OPEN | CLI |
| C2 | `run` JSON envelope always | — | §11 | FIXED✓ | run |
| C3 | Every arg has help | — | §11 | OPEN | CLI |
| C4 | `--input` @file/stdin | — | §11 | FIXED✓ | run |
| C5 | First-class `export` | §12 | §6,§11 | OPEN | CLI |
| C6 | Every tool dispatchable | — | §11 | FIXED✓ | all |
| C7 | Keyless/offline first-run | — | §10 | FIXED✓ | CLI+shell |
| C8 | Model↔backend preflight | — | §10 | OPEN | all |
| C9 | First-run not inert | — | §10 | OPEN | shell |

---

## Appendix — build order (non-normative)

The FRs are independent; a sensible sequencing when the work is scheduled:

1. **Interaction grammar (A2.1–A2.3, A1.3)** — highest operator-friction, self-
   contained in `state_transitions/` + `commands/`, all shell-only, testable
   without model/network. Ship as one coherent grammar change.
2. **Terminal robustness (A3.1–A3.2)** — unblocks correct rendering on the
   platform operators are actually on; isolated to `theme/` + `renderer/shared/text/`.
3. **Headless polish (C1, C3, C5, C8)** — CI-facing, small, high-trust.
4. **First-run orientation (B1.5, C9)** — closes the last first-contact gaps.
5. **Reframe surfaces (B2, B3, B6)** — the `NEW` control-room capabilities; larger,
   depend on the harness/sweep/strategy work in the PRD rollout waves (PRD §14).

Each item lands with the acceptance test named in its FR, passes
`pnpm quality:crap-risk` (complexity ≤4, ≤40 logical lines, risk <7), and keeps
`cargo test -p kuzushi-tui` + clippy clean.
