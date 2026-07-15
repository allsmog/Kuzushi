# Plan 038: Make every phase and foreground question adapt to truthful content

> **Executor instructions**: Begin only after Plan 037 is complete and the
> operator approves the audit wireframes. Preserve all dirty user-owned work.
> Run every verification and stop on the conditions below. Update the Plan 038
> row in `plans/README.md` when complete.
>
> **Drift check (run first)**: inspect committed, dirty, and untracked changes
> across the complete renderer/view-model/doc scope.

```zsh
drift_paths=(
  crates/kuzushi-tui/src/renderer/views/workbench
  crates/kuzushi-tui/src/renderer/render_app.rs
  crates/kuzushi-tui/src/renderer/section_slot.rs
  crates/kuzushi-tui/src/renderer/snapshots/phase_cockpit
  crates/kuzushi-tui/src/ui_view_models
  docs/design/terminal-cockpit-reference.md
  docs/design/product-flow-design-spec.md
)
git diff --stat 76974ccf5..HEAD -- "${drift_paths[@]}"
git diff --stat -- "${drift_paths[@]}"
git status --short -- "${drift_paths[@]}"
```

Any competing hierarchy, card-sizing, or adaptive-layout work is a STOP
condition until reconciled with the approved Plan 037 contract.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: Plan 037; operator approval of wireframes/thresholds
- **Category**: bug / UX / accessibility
- **Planned at**: commit `76974ccf5`, 2026-07-14

## Why this matters

Plan 037 makes geometry and interaction coherent. This plan aligns each
phase's visible hierarchy with its operator task, removes blank-pane defaults,
and gives Guided/ResultReady the sole attention region without deleting any
capability. It also corrects Fix's inverted hierarchy and narrow Review's
duplicated detail.

## Current state

- Canonical screen order is target/reality, truth, NEXT, supporting evidence
  (`docs/design/terminal-cockpit-reference.md:23-32`).
- Missing Map artifacts should be one actionable hint and visualizations remain
  contextual decks (`:219-221`).
- Review is queue + selected detail (`:248-265`).
- Prove keeps identity/STATUS/NEXT before evidence (`:267-288`).
- Fix requires Remediation focused after Apply (`:294-320`).
- Guided card reserves up to 45% of height
  (`renderer/views/workbench/guided_scan.rs:8-20`) while normal body accents
  remain active (`render_workbench_view.rs:35-47`).
- Guided fitting uses scalar count rather than display columns
  (`guided_scan.rs:265-326`).
- Existing `Z` decks prove Project Context, Attack Surface, Engine Outcomes,
  Review detail, Prove evidence/proof, and Fix remediation remain reachable.

Approved hierarchy target:

- Map: coverage/readiness primary; selected artifact detail; contextual viz.
- Scan: engine outcomes primary; selected receipt detail; nonempty delta/failure
  as optional third.
- Review: queue + selected detail; one inline queue at narrow sizes.
- Prove: status/NEXT fixed first; evidence primary; proof/receipt only if real.
- Fix: remediation/candidate lifecycle primary; diff detail; one contextual
  diagram only in meaningful Dense mode.
- Guided/ResultReady: card owns input/accent; body is a quiet summary.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Format | `cargo fmt --all -- --check` | exit 0 |
| Focused render tests | `cargo test -p kuzushi-tui adaptive_phase --offline` | pass |
| Snapshots | `cargo test -p kuzushi-tui phase_composition_contract --offline` | approved goldens pass |
| Full TUI | `cargo test -p kuzushi-tui --offline` | pass |
| Clippy | `cargo clippy --offline -p kuzushi-tui --all-targets -- -D warnings` | pass |
| CRAP | `pnpm quality:crap-risk` | pass |
| Docs | `pnpm check:docs` | pass |

## Scope

**In scope**:

- `renderer/views/workbench/phase_pages/{map,scan,hunt,confirm,fix}.rs` and
  their cohesive submodules/tests
- `renderer/views/workbench/phase_pages/header.rs`
- `renderer/views/workbench/render_workbench_view.rs`
- `renderer/views/workbench/guided_scan.rs` and tests
- `renderer/render_app.rs` / `section_slot.rs` only for attention/body contract
- phase line/view-model helpers when semantic summary data is missing
- relevant snapshots
- `docs/design/terminal-cockpit-reference.md`
- `docs/design/product-flow-design-spec.md`

**Out of scope**:

- execution/runtime/model policy;
- durable reality/journey derivation;
- persistence caching (Plan 039);
- exhaustive fixture/journey infrastructure (Plan 040);
- changing visualization data or removing focused decks.

## Git workflow

Work in the current dirty branch unless directed otherwise. Preserve overlapping
hunks. Do not stage/commit/push without explicit authorization.

## Steps

### Step 1: Implement Map and Scan Sparse/MasterDetail/Dense compositions

Map Sparse renders coverage/readiness rows and one NEXT. Map detail follows the
selected meaningful artifact. Scan Sparse renders attempt outcome/scope/engine
count/delta/NEXT; Scan MD renders outcomes + selected receipt. Add a third
surface only for independently useful nonempty data.

Do not use line count as occupancy. Do not render empty pane borders.

**Verify**: Empty/Sparse/Partial/Dense fixtures at all five sizes assert the
planned visible semantic IDs and key atoms.

### Step 2: Make Review and Prove progressive

At 40x12/60x20, Review is one queue with inline identity/STATUS/NEXT. At wider
sizes it is queue + selected detail. An empty selection never reserves detail.

Prove always places identity/STATUS/NEXT first. Missing runtime proof is a row,
not a standalone pane. Dense three-surface Prove requires meaningful evidence,
ladder, and current verification receipt.

**Verify**: narrow Review has one selection region and useful queue budget;
empty/missing-proof Prove has no empty proof pane; stale-proof warning survives
40x12.

### Step 3: Recenter Fix on Remediation

Make Remediation primary/default focus. Put selected candidate/diff/lifecycle
in MD detail. Add at most one real Attack Tree or DFD surface in Dense; the
other remains a readiness row and focused deck. Successful Apply and Report
return to Remediation with touched paths and exact reverify action.

Keep Apply visibly separate and authorization-bound. Do not alter patch policy
or mutation behavior.

**Verify**: applied/staged/draft/reverify states show lifecycle and NEXT before
diagrams; long receipts scroll; Apply returns to visible Remediation.

### Step 4: Give Guided and ResultReady one attention owner

Reserve the card first and request a Guided plan for the remaining body. Keep
phase/reality/target/NEXT plus no more than three quiet summary rows. Remove or
mute ordinary body selection band; hidden surfaces are not focusable or
hit-testable. Background questions keep normal layout/focus but promote a
waiting-input priority atom at 40x12.

ResultReady uses the same policy unless the operator approved a more compact
receipt-only variant.

**Verify**: Map/Scan guided and Scan result cards at all five sizes have one
accent, visible NEXT, visible selected card row, and exact resize restoration.

### Step 5: Fix terminal-column fitting and no-color hierarchy

Replace local `chars().count()` fit/pad with the shared Unicode-width helper.
Keep words/glyphs for status, stale, failure, proof, waiting input, and
selection. Confirm high-contrast/no-color does not turn empty borders into the
dominant feature.

**Verify**: CJK, emoji, and combining cases remain in bounds at 40x12/60x20;
no-color semantic assertions pass.

### Step 6: Update canonical docs and focused verification

Document adaptive density as the canonical presentation contract and retain
focused decks as the capability-preservation mechanism. Do not describe
`depends_on`/execution or other unrelated product behavior.

Run every command in the table and inspect changed files for long functions,
duplicated layout branches, stale Hunt/Confirm wording, and needless API
expansion.

## Test plan

- Map/Scan fixtures: empty, one surface, two surfaces, three real surfaces,
  stale/blocked status rows, guided/result.
- Review: no selection, one selection narrow/wide, pinned disclosure.
- Prove: no finding, missing proof, current proof, stale proof, replay.
- Fix: draft/staged/applied/reverify outcomes, long touched paths, missing
  diagrams, one/two diagrams.
- Profiles: truecolor, ANSI-256, high contrast, no color.
- Focused decks: every hidden surface remains reachable and restores origin.

## Done criteria

- [ ] Empty/sparse pages reserve no blank pane regions.
- [ ] Automatic Dense mode has at most three meaningful surfaces.
- [ ] Map/Scan/Review/Prove/Fix match approved task hierarchy.
- [ ] Fix Remediation is primary and post-Apply focus.
- [ ] Guided/ResultReady have one attention owner and no hidden focus.
- [ ] Background waiting input survives 40x12.
- [ ] Unicode/no-color tests pass.
- [ ] Full TUI, Clippy, CRAP, docs, and formatting gates pass.

## STOP conditions

- Operator has not approved Dense geometry, Fix hierarchy, or ResultReady
  behavior.
- Plan 037's semantic surface/geometry API is missing or diverged.
- Required UI behavior would change durable journey truth or execution policy.
- Existing views cannot remain reachable through approved focused decks.
- Any focused verification fails twice after bounded correction.

## Maintenance notes

Reviewers should compare task hierarchy, not screenshot similarity alone.
Future empty states must add a truthful row and action before asking for a new
pane.
