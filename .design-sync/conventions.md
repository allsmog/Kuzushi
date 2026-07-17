# Kuzushi TUI Kit — current implementation contract

This design-sync project mirrors the current Rust Ratatui shell. It is a
reference for designing from the product Kuzushi actually ships; it is not a
proposal, a chat transcript, or a replacement workflow. Preserve Kuzushi's
security lifecycle, typed outcomes, and source-backed truth.

The reference baseline is branch `codex/atlas-native-cockpit` at
`ccb29faec323b52300b3f28e35bd85473ad841d7`. The canonical visual fixtures are
the committed phase-cockpit snapshots under
`crates/kuzushi-tui/src/renderer/snapshots/phase_cockpit/` and the route
snapshots under `crates/kuzushi-tui/tests/snapshots/`.

## Shell anatomy

A normal phase page reads from top to bottom as:

1. A one-line context strip: `KUZUSHI · VIEW <PHASE>` plus honest reality,
   target, liveness, cost, context, model, and active module facts when space
   permits.
2. The reality-derived five-phase rail: `組 map · 崩 scan · 覧 review · 証 prove
   · 掛 fix`. Visiting a page never advances this rail.
3. One `▸ NEXT` action and a short page-specific action line.
4. The phase-owned cockpit body. At 120 columns it may expose three useful
   panes; at 80 it normally exposes two; constrained terminals keep only the
   primary pane.
5. A compact status footer and only the bindings that work on this view.
6. The phase composer at the bottom:
   `◇ MAP ›`, `▦ SCAN ›`, `▣ REVIEW ›`, `◎ PROVE ›`, or `◆ FIX ›`.

Run Focus is the exception: active work owns the whole frame with its own run
header, health line, adaptive TASKS/OUTPUT panes, and controls. Setup and target
selection likewise own their guidance instead of inheriting generic transcript
chrome.

## The planning workflow stays at the bottom

The bottom planner is a current product contract and must not disappear.

- The phase composer is always the last row of every Map, Scan, Review, Prove,
  and Fix page.
- Submitting a bare phase intent launches the phase-constrained planner in Run
  Focus. The active run is work, not history.
- When the planner returns, a conditional `◆ PLAN · goal: … · X/Y active`
  proposal card appears immediately above the same phase composer.
- The operator reviews changes with `j/k`, toggles with `Space`, applies active
  changes with `y`, or discards with `n`. `/yes` and `/no` remain command
  equivalents.
- The proposal card is not permanent chrome. Represent all three real states:
  phase prompt, planner running in Run Focus, and returned plan proposal.

## Canonical screens and families

- Target Picker → Setup → Map → Scan → Review → Prove → Fix → Report is the
  engagement spine.
- `PhaseCockpit` covers the five durable pages. Its content differs by phase:
  project context/attack surface, recorded engine receipts, review
  queue/detail, evidence/proof ladder, and remediation/report/attack tree.
- `RunFocus` covers active, waiting, completed, partial, failed, canceled, and
  interrupted run truth. Completion is a terminal state, never an eternal
  spinner.
- `AttentionCard` covers typed questions, confirmations, credential gates, and
  approvals. Attention replaces normal input while it is unresolved.
- `RouteScreen` covers the line-oriented families such as Capabilities, Jobs,
  Runs, Replay, Trace, Help, Auth, Config, Permissions, Cost, Logs, Context,
  Workspace, Knowledge Base, editors, and recovery surfaces. These retain the
  shared context/status grammar without becoming phase cockpits.
- Scene/visualization decks are contextual views over real artifacts and
  return to their exact origin.

## Responsive contract

- `40×12`: constrained fallback. Keep location, honest state, NEXT, one focal
  pane, the minimal footer, and the phase composer. Omit the rail and secondary
  panes before truncating the focal result.
- `60×20`: compact single/stacked content with wrapped footer hints.
- `80×24`: primary target. Two useful panes, short header, full composer.
- `120×36`: primary target. Up to three phase-specific panes and complete
  supporting detail.
- `160×48`: expose more evidence, claim/provenance detail, or diagrams. Do not
  stretch labels and paths across the empty width.

Never hide detail without a visible inspect, scroll, replay, trace, or zoom
action. Long paths, run IDs, fingerprints, models, and revisions are compact by
default and exact in detail surfaces.

## Visual grammar

The palette is copied from `crates/kuzushi-tui/src/theme/mod.rs`:

- background `#0b0d10`
- primary `#cfd6e0`, muted `#7d8794`, subtle `#3d4654`
- accent `#7fb8ff`, label `#a6cdff`, heading `#ffffff`
- success `#57c479`, warning `#e2c14a`, danger `#e25c5c`
- phase identity: Map `#3dc7b5`, Scan `#e7b94b`, Review `#66a9ff`,
  Prove `#b57cff`, Fix `#ee72b7`

Color never carries status alone. Preserve the words and glyphs (`✓`, `●`,
`⚠`, `!`, `×`, `⊘`, `·`). Use thin left pane rails and terminal rules; avoid
decorative cards, fake macOS window controls, decorative gradients, emoji, or
generic chat bubbles. The current one-row cinematic scanline texture on
Workbench and Run Focus is the only gradient-backed surface treatment in this
reference.

## Truth and hierarchy rules

- Current state, latest terminal result, and historical receipts are distinct.
- One fact has one primary home; do not repeat phase, status, result, cost, or
  NEXT in multiple regions.
- Results retain outcome, source, artifact durability, cost completeness, and
  recommended next action. Partial, degraded, canceled, interrupted, skipped,
  and failed are not styled as success.
- Findings retain alias, severity, confidence, evidence count, decision,
  lifecycle, proof, and source identity.
- Fix retains draft → staged → applied → reverified history.
- Descriptor-backed tool names and shared scan/shell/run behavior remain
  operational truth. Do not invent tools, evidence, proof, artifacts, or cost.
- Never expose hidden chain-of-thought. Run output is an operator-visible event
  feed and artifact trail.

## Component use

Import `@kuzushi/tui-kit/styles.css` once. Build from the shipped components:

- `TerminalFrame` — neutral terminal viewport and exact cell dimensions.
- `PhaseRail`, `PhasePrompt`, `PlanningCard` — shared journey and bottom
  planning grammar.
- `PhaseCockpit` — Map/Scan/Review/Prove/Fix full-screen reference.
- `RunFocus` — live and terminal run states.
- `SetupScreen` — aggregate readiness before Start Map.
- `AttentionCard` — question/confirmation/credential/approval gates.
- `RouteScreen` — shared line-oriented route families.

The authored previews are representative current-state fixtures. Treat them as
implementation references, not suggested redesigns.
