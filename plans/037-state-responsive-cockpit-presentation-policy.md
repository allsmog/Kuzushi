# Plan 037: Make cockpit layout one semantic presentation policy

> **Executor instructions**: This plan is not approved merely because it
> exists. Start only after the operator approves the audit mockups and the
> semantic-route migration. Follow every step and verification gate. Preserve
> all user-owned work in the dirty tree. If a STOP condition occurs, report it
> instead of improvising. When complete, update Plan 037 in `plans/README.md`.
>
> **Drift check (run first)**: run all three commands below. The first shows
> committed drift since the audit, the second shows unstaged/staged working-tree
> drift, and the third exposes untracked or otherwise dirty scoped files.

```zsh
drift_paths=(
  crates/kuzushi-tui/src/ui_view_models/phase_cockpit
  crates/kuzushi-tui/src/ui_view_models/workbench_frame_layout.rs
  crates/kuzushi-tui/src/ui_view_models/keybindings/workbench.rs
  crates/kuzushi-tui/src/app/view_state
  crates/kuzushi-tui/src/app/state_transitions
  crates/kuzushi-tui/src/renderer/render_app.rs
  crates/kuzushi-tui/src/renderer/section_slot.rs
  crates/kuzushi-tui/src/renderer/views/workbench
)
git diff --stat 76974ccf5..HEAD -- "${drift_paths[@]}"
git diff --stat -- "${drift_paths[@]}"
git status --short -- "${drift_paths[@]}"
```

Compare all symbols and line references below against both committed and dirty
output. Any changed semantic ownership or an in-progress competing layout
policy is a STOP condition.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: none; operator approval required
- **Category**: bug / tech-debt / presentation architecture
- **Planned at**: commit `76974ccf5`, 2026-07-14

## Why this matters

Current geometry is selected from phase and terminal dimensions while semantic
models already know which artifacts, selections, receipts, and proofs exist.
This creates blank wide-screen quadrants, phantom keyboard focus, and a mouse
hit map unrelated to what Ratatui painted. One pure plan must own visible
surfaces, geometry, focusability, scroll behavior, and hit-testing so all input
and rendering agree.

## Current state

- `ui_view_models/phase_cockpit/mod.rs:65-198` owns truthful phase DTOs with
  optional/empty semantic content.
- `renderer/views/workbench/phase_pages/map.rs:18-35` and
  `scan.rs:23-35` choose compact/grid from dimensions alone.
- `renderer/views/workbench/phase_pages/hunt.rs:14-30` always creates Review
  queue and detail regions.
- `renderer/views/workbench/phase_pages/confirm.rs:23-44,225-268` special-cases
  no selection but otherwise uses dimension-only topology.
- `renderer/views/workbench/phase_pages/fix.rs:23-90` allocates report,
  diagrams, and remediation from dimensions.
- `app/view_state/sast_task_row.rs:336-392` separately approximates visible
  pane order from full terminal size.
- `app/state_transitions/text_input.rs:184-323` hit-tests retired generic
  four/three-column layouts.
- `app/state_transitions/view_hotkey_actions.rs:180-213` and
  `sast_task_row.rs:466-507` route behavior through generic pane aliases;
  Fix Remediation therefore cannot scroll.
- `renderer/render_app.rs:43-68,206-216` and `renderer/section_slot.rs:9-61`
  own primary/chrome/question allocation, while Workbench input currently has
  no exact post-chrome rectangle.
- `ui_view_models/activity_layout.rs:25-47` is the repository exemplar for a
  pure geometry policy shared by rendering and hit-testing.
- Canonical vocabulary is Map/Scan/Review/Prove/Fix; legacy `hunt`/`confirm`
  module filenames are implementation debt, not user-facing terminology.

The policy contract to introduce is:

```text
LayoutDensity = Sparse | MasterDetail | Dense | Focused | Guided
PhaseSurfaceId = semantic phase-owned surface identity
PhasePresentationPlan = density + primary + visible/focusable order +
                        rectangles + interaction kinds + attention owner
```

Semantic state, never rendered line counts, decides whether a surface is
meaningful. The exact available body rectangle is calculated after phase
header, question/result card, footer, and other chrome.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Focused tests | `cargo test -p kuzushi-tui phase_presentation --offline` | all new policy tests pass |
| TUI tests | `cargo test -p kuzushi-tui --offline` | exit 0 |
| Lint | `cargo clippy --offline -p kuzushi-tui --all-targets -- -D warnings` | exit 0 |
| CRAP gate | `pnpm quality:crap-risk` | risk below repo threshold |

## Scope

**In scope**:

- `crates/kuzushi-tui/src/ui_view_models/phase_cockpit/layout.rs` (new)
- `crates/kuzushi-tui/src/ui_view_models/workbench_frame_layout.rs` (new shared
  root-frame/card geometry; renderer-agnostic)
- `crates/kuzushi-tui/src/ui_view_models/phase_cockpit/mod.rs`
- `crates/kuzushi-tui/src/app/view_state/sast_task_row.rs`
- `crates/kuzushi-tui/src/app/view_state/routes.rs` only if semantic focus
  migration needs a compatibility field
- `crates/kuzushi-tui/src/renderer/views/workbench/phase_pages/mod.rs`
- `crates/kuzushi-tui/src/renderer/render_app.rs`
- `crates/kuzushi-tui/src/renderer/section_slot.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/render_workbench_view.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/guided_scan.rs` only to
  consume the shared card-height calculation
- the five phase-page renderer modules only where they consume returned rects
- `crates/kuzushi-tui/src/app/state_transitions/text_input.rs`
- `crates/kuzushi-tui/src/app/state_transitions/view_hotkey_actions.rs`
- `crates/kuzushi-tui/src/ui_view_models/keybindings/workbench.rs`
- focused unit tests beside these modules

**Out of scope**:

- changing persisted phase reality or `.kuzushi` formats;
- changing module/descriptor execution;
- redesigning phase copy or diagram visuals (Plan 038);
- persistence/projection caching (Plan 039);
- broad golden/live matrix expansion (Plan 040);
- removing compatibility aliases without a migration window.

## Git workflow

- Work in place on the operator's active branch unless explicitly directed to
  create another `codex/` branch.
- Do not reset, clean, replace whole files, stage, commit, push, or open a PR
  without explicit operator authorization.
- Before every edit, inspect overlapping dirty hunks and preserve them.

## Steps

### Step 1: Add semantic surface identities and occupancy

Create `phase_cockpit/layout.rs` with cohesive, pure types:

- `LayoutDensity`;
- `PhaseSurfaceId` variants scoped to phase concepts;
- `SurfaceState::{Missing, Available, Stale, Blocked}` or an equally explicit
  value that distinguishes a status row from a meaningful independent surface;
- `SurfaceInteraction::{Static, Selectable, Scrollable, Diagram}`;
- a small occupancy projection from `PhaseCockpitBody`.

Do not read filesystem, env, terminal, stores, or app state in this module. Do
not make it generic over arbitrary UI frameworks.

**Verify**: `cargo test -p kuzushi-tui phase_surface_occupancy --offline` ->
tests prove empty hints are rows, selected real detail is meaningful, and each
phase maps to canonical semantic IDs.

### Step 2: Derive one pure `PhasePresentationPlan`

Accept the semantic body, exact available `Rect`, current semantic focus,
attention mode, and optional explicit focus. Return density, primary, visible
and focusable order, interaction kinds, and rectangles.

Required invariants:

- Guided/Focused override normal density;
- Sparse for zero/one meaningful surfaces or insufficient exact body;
- MasterDetail only when meaningful detail exists;
- Dense requires at least three meaningful surfaces and is capped at three;
- every focusable surface has one visible nonempty rectangle;
- rectangles do not overlap and remain inside body;
- a hidden prior focus produces a visible temporary fallback without deleting
  the stored semantic focus.

Keep functions under repository complexity/length thresholds. Extract
phase-specific priority tables rather than one nested match tree.

**Verify**: `cargo test -p kuzushi-tui phase_presentation_plan --offline` ->
all five phases pass Empty/Sparse/Partial/Dense at the five canonical sizes.

### Step 3: Share exact root-frame and phase-body geometry

Extract the Workbench root allocation now split between `render_app.rs`,
`section_slot.rs`, `guided_scan.rs`, and `render_workbench_view.rs` into the
pure `ui_view_models/workbench_frame_layout.rs`. Define
`WorkbenchFrameLayoutInput` from viewport, ordered chrome-slot heights,
phase-header rows, zoom row, and foreground question/result-card model. Return
`WorkbenchFrameLayout` with terminal-coordinate rectangles for primary,
phase header, exact phase body, foreground card/input, every lower chrome slot,
and footer/prompt.

Move the existing guided-card height recipe behind this shared input adapter;
Plan 038 may change its Unicode-aware measurement, but renderer and input must
always call the same function. `render_app`, `render_workbench_view`, and
mouse/input routing independently derive the same immutable frame layout from
the current `ShellApp` plus `TerminalViewport`; do not cache a mutable
"last-rendered rect". The `PhasePresentationPlan` consumes only the returned
exact phase-body rectangle and returns terminal-coordinate surface rectangles.

Replace renderer-local `Layout::split` topology decisions with those returned
semantic rectangles while preserving existing line builders and visual content
for this plan. Eliminate parallel full-viewport pane normalization in
`PhaseRenderState`.

Do not infer semantic occupancy from line-vector length. Do not add one layout
planner per phase renderer.

**Verify**: `cargo test -p kuzushi-tui phase_presentation --offline` -> every
painted semantic surface is present exactly once in the plan and all existing
focused-deck tests remain green.

### Step 4: Move focus, scrolling, zoom, and key hints to semantic surfaces

Adapt generic `WorkbenchPane` state at one compatibility boundary. Pane cycle,
`Z`, `z`, list movement, and scroll routing must consume the plan's focusable
order and interaction kind. Fix Remediation must be Scrollable; a diagram must
not receive list movement.

Preserve stored selection/scroll across resize and Guided hiding. If a surface
is absent after a durable data refresh, choose the approved explicit-empty or
origin-return behavior rather than silently redirecting an action.

**Verify**: focused tests cycle every density and prove that no key action can
target a surface without a rectangle; long Fix Remediation scrolls normally
and under `Z`.

### Step 5: Replace generic mouse geometry with plan rectangles

In `ShellApp::workbench_pane_for_mouse`, derive `WorkbenchFrameLayout` from the
same shared function used by render, derive `PhasePresentationPlan` from its
`phase_body`, and hit-test the plan's terminal-coordinate rectangles directly.
Header, question/result card, lower chrome, footer, and blank gaps must return
no phase surface and must not change focus. Remove the retired `FourColumn`,
`ThreeColumn`, `Stacked`, and `ShortReview` contract only after these semantic
tests pass. Scroll routing must resolve the same hit surface before applying
its interaction kind.

**Verify**: `cargo test -p kuzushi-tui workbench_mouse --offline` -> center and
edge clicks map to the exact semantic surface at Sparse, MasterDetail, Dense,
and Guided sizes.

### Step 6: Complete compatibility and quality gates

Ensure current public/persisted contracts remain stable or document a narrowly
approved migration. Scan/shell/run dispatch and durable reality must be
untouched. Run all commands in the command table.

**Verify**: every command exits 0 and `git diff --check` prints nothing.

## Test plan

- Pure table tests: five phases x occupancy classes x five sizes.
- Property invariants: plan rectangles in bounds/non-overlapping; focusable is
  a subset of visible; max three automatic panes; exactly one primary.
- Interaction tests: cycle, resize fallback/restore, zoom, scroll behavior,
  mouse centers/edges, header/card exclusion.
- Compatibility tests: legacy generic route focus loads into the intended
  semantic surface; no phase/durable reality changes.
- Structural exemplar: match `ui_view_models/activity_layout.rs` purity.

## Done criteria

- [ ] One pure plan owns density, semantic surfaces, rects, and focus order.
- [ ] Renderer and input derive the same exact post-chrome/post-card body rect.
- [ ] No phase renderer or input path maintains competing topology heuristics.
- [ ] Compact Map/Prove have no phantom focus.
- [ ] Fix Remediation scrolls and can be the semantic primary.
- [ ] Mouse hit-testing uses rendered rectangles.
- [ ] All focused tests, full TUI tests, Clippy, formatting, and CRAP gate pass.
- [ ] No files outside scope are modified except approved `plans/README.md`.

## STOP conditions

- An overlapping user-owned refactor already introduces a presentation policy.
- Semantic focus requires changing durable phase reality or `.kuzushi` formats.
- Exact body geometry cannot be made available without redesigning root frame
  ownership beyond scoped files.
- Compatibility needs silent action redirection or loses stored selection.
- A verification failure repeats twice after a bounded fix.

## Maintenance notes

Every future phase surface must declare semantic identity, occupancy, priority,
and interaction behavior before rendering. Reviewers should reject new
renderer-local breakpoint logic or input-only geometry.
