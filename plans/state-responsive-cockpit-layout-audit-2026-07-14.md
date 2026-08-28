# State-responsive cockpit layout audit

**Date:** 2026-07-14

**Repository:** `/workspace/Kuzushi`

**Audited binary:** `kuzushi 0.24.0-alpha.8 (76974ccf5+dirty · debug)`

**Decision status:** mockups and plan proposed; implementation requires approval

**Direct recommendation:** **use a hybrid** — replace automatic simultaneous
four-quadrant presentation with adaptive layouts, while preserving every
existing surface as a semantic detail or focused `Z` deck.

## 1. Executive summary

The current cockpit is truthful about phase and durable reality, and its
compact modes, focused decks, plain output, and no-color semantics are useful
foundations. The default wide-screen composition is not state-responsive,
however. Map, Scan, Review, and Fix decide geometry from terminal dimensions
and phase identity, not from whether their semantic surfaces contain useful
data. At 120x36 and 160x48 this turns empty hints, one-row outcomes, and absent
artifacts into equally weighted quadrants. Borders and blank regions become
more visually prominent than the operator's next decision.

This is not only an information-density issue:

- foreground questions can reduce the rendered body to one compact surface
  while keyboard focus still exposes four logical panes;
- compact Map and Prove can cycle focus through panes that are not visible;
- mouse hit-testing still uses a retired generic four/three-column geometry;
- Fix makes Attack Tree the primary focus and maps action-bearing Remediation
  to a non-scrollable generic Findings pane;
- selected, target-backed Fix rebuilds remediation truth by opening SQLite in
  the render path;
- the existing 120-buffer contract is green, but all cells reuse one rich
  fixture and therefore cannot detect the empty/sparse/guided failures.

The proposed design preserves product capability and changes presentation
policy. A pure `PhasePresentationPlan` should derive
`Sparse | MasterDetail | Dense | Focused | Guided` from semantic occupancy,
selection, attention, and the exact post-chrome body rectangle. Rendering,
keyboard focus, scrolling, zoom, and mouse hit-testing must consume the same
semantic surface plan. Dense mode should expose at most three meaningful
regions; the four-quadrant grid should not remain an automatic default.

## 2. Audit boundary and provenance

The audit began by inventorying the active tree and preserving its 467
pre-existing changed/untracked entries. Its complete write surface is the
untracked audit report, Plans 037-040, isolated `plans/artifacts/`, and the four
new `TODO` rows plus approval note in `plans/README.md`. No product source was
edited.

| Item | Observed |
|---|---|
| Branch | `codex/atlas-native-cockpit` |
| HEAD | `76974ccf5ce94f2cc099489ab4dcadfb1f5cb440` |
| Live binary | `target/debug/kuzushi` |
| Binary timestamp | `2026-07-14 12:19:09 -0700` |
| tmux | `3.6a` |
| Warp | live `/Applications/Warp.app/Contents/MacOS/stable` process |
| Profiles | truecolor, ANSI-256, high contrast, no color, plain |
| Sizes | 40x12, 60x20, 80x24, 120x36, 160x48 |

The live captures use the most recent existing compiled binary rather than a
replacement audit build. Some user-owned source files were edited after that
binary timestamp while the audit was in progress. The layout owners behind
the findings (`map.rs`, `scan.rs`, `hunt.rs`, `confirm.rs`, `fix.rs`, focus,
mouse, and scroll policy) did not change underneath the live evidence. Every
implementation plan begins with a drift check because this dirty branch is
actively evolving.

Capture provenance and method are recorded in
[`artifacts/state-responsive-cockpit-audit-2026-07-14/README.md`](./artifacts/state-responsive-cockpit-audit-2026-07-14/README.md).
Accepted captures were taken only with tmux `alternate_on=1`. Resize captures
use the same running process and wait for Ratatui to acknowledge the requested
width before saving text and ANSI frames.

Representative evidence:

- [direct Warp window capture](./artifacts/state-responsive-cockpit-audit-2026-07-14/warp/warp-kuzushi-waiting-input.png)
- [empty Map at 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/empty/map-120x36.txt)
- [fully populated reference Map at 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/map-160x48.txt)
- [fully populated reference Scan at 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/scan-160x48.txt)
- [guided Map at 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/guided-map/map-guided-120x36.txt)
- [guided Scan at 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/guided-scan/scan-guided-120x36.txt)
- [result-ready Scan at 40x12](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/result-ready/scan-result-ready-40x12.txt)
- [explicit-model blocked Scan at 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/blocked/scan-blocked-aftermath-120x36.txt)
- [background question, Review at 40x12](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/background/review-background-40x12.txt)
- [focused Fix Remediation deck](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/focused/fix-remediation-zoom-120x36.txt)

The existing renderer contract also passed:

```text
cargo test -p kuzushi-tui phase_composition_contract --offline -- --nocapture
test result: ok. 5 passed; 0 failed; 1946 filtered out
```

That is useful corroboration, not live-state proof: its 120 cells are five
phases x six sizes x four profiles over one fully populated fixture.

## 3. Live audit coverage

Legend: `L5` = live at all five requested sizes; `L` = live representative
state; `S5` = simulated semantic state at all five sizes; `M` = model/source
inspection only; `--` = no deterministic current route. A simulated cell is
not promoted to production behavior.

| Phase | Empty | Sparse | Partial | Dense | Stale | Blocked | Result ready | Guided | Background |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Map | L5 | L5 | L5 | M | S5 | M | M | L5 | L5 |
| Scan | L5 | L5 | L5 | M | S5 | L5 | L5 | L5 | L5 |
| Review | L5 | M | M | L5 | M | M | M | M | L5 |
| Prove | L5 | M | L5 | M | L5 (stale proof only) | M | M | M | L5 |
| Fix | L5 | M | L5 | M | M | M | M | M | L5 |

The table classifies the semantic body on each page, not just the target used to
launch it. For example, the sparse target gives Map/Scan meaningful sparse
content but Review/Prove are still empty. The settled DevEx fixture populates
every surface, but only Review has a list/selection that clearly meets the
request's Dense definition; the other pages are recorded as Partial and Dense
remains a test/source gap. The deterministic live product route currently
exposes foreground guided questions for Map and Scan. Review/Prove/Fix
attention variants are not selectable from the compiled fixture, which is
itself a regression-coverage gap. Stale context was simulated by retaining a
context snapshot for a prior target/revision and setting its canonical
`staleSlices`; the phase pages did not surface that marker. This proves only
that the presentation does not consume the seeded stale semantic field, not
that every production staleness detector fails.
Prove's `L5` Stale cell is the distinct production stale-proof receipt warning,
not a claim that the simulated cross-target `staleSlices` state surfaced.
Map Blocked remains source/model-only: the deterministic live blocked route
belongs to Scan, and no Map-specific blocked frame is claimed.

`live/excluded-result-ready-map-race/` is excluded: a queued key advanced into
a Scan module question before the resize loop. The valid result-ready evidence
is the stable, polled live Scan completion under `live/result-ready/`.

## 4. Current behavior and recommended density matrix

### 4.1 What the current binary does

| Phase | 40x12 | 60x20 | 80x24 | 120x36 | 160x48 |
|---|---|---|---|---|---|
| Map | one combined summary | combined narrative | 2x2 | 2x2 | 2x2 |
| Scan | one combined summary | combined narrative | 2x2 | 2x2 | 2x2 |
| Review | vertical queue/detail | vertical queue/detail | 44/56 master-detail | 44/56 master-detail | 44/56 master-detail |
| Prove | critical status summary | status + combined evidence | status + evidence/proof | status + evidence/proof | status + evidence/proof |
| Fix | combined report | combined report/diagrams/remediation | combined | report + two diagrams + remediation | report + two diagrams + remediation |

Map and Scan already demonstrate that compact, line-based presentation is
possible. Their wide transitions are purely geometric, so even an entirely
empty Map becomes a four-region canvas at 120x36. Review is the closest dense
precedent, but its narrow vertical split duplicates selected detail and halves
the useful queue. Prove has the best true empty state, yet exposes phantom
focus after its renderer collapses. Fix has the least task-aligned wide
hierarchy.

### 4.2 Recommended phase x size default

Codes: `S` Sparse, `MD` MasterDetail, `D` Dense. `/D` means Dense is permitted
only when semantic thresholds pass. `G` and `F` override every size when a
foreground attention card or explicit focused deck is active.

| Phase | 40x12 | 60x20 | 80x24 | 120x36 | 160x48 |
|---|---:|---:|---:|---:|---:|
| Map | S | S | MD when detail exists | MD/D | D only with 3 real surfaces |
| Scan | S | S | MD when an outcome is selected | MD/D | D only with independent failure/receipt data |
| Review | S | S | MD | MD | MD; no third pane by default |
| Prove | S | S | MD | MD | D only with evidence + ladder + current receipt |
| Fix | S | S | MD | MD/D | D only with remediation + diff + real context |
| Any foreground question/result | G | G | G | G | G |
| Any explicit `Z` deck | F | F | F | F | F |

Terminal size is a ceiling, not a reason to manufacture regions. Empty,
missing, stale, unavailable, and blocked values remain labeled rows inside the
primary narrative unless they have independent actions and enough real detail
to justify a surface.

## 5. Panel inventory and cognitive walkthrough

| Phase | Current surface | Semantic purpose | Proposed role |
|---|---|---|---|
| Map | Project Context (`Source`) | target/revision, context, inventory, readiness | primary coverage list |
| Map | Attack Surface (`Center`) | entry points and risk groups | selected detail or dense third surface |
| Map | Hot Modules (`Findings`) | severity-weighted finding modules | contextual detail after Scan; heatmap deck |
| Map | Threat Model / DFD (`Details`) | threat zones, nodes, flows | readiness row; DFD focused deck |
| Scan | Scope / Plan (`Source`) | target scope and selected engine plan | summary above outcome list |
| Scan | Engine Outcomes (`Center`) | per-engine terminal truth | primary selectable list |
| Scan | Finding / Artifact Delta (`Findings`) | outcome delta | compact status; third surface only if substantial |
| Scan | Receipt (`Details`) | run, duration, cost, freshness, errors | selected outcome detail |
| Review | Findings (`Findings`) | confidence-first actionable queue | primary selectable list |
| Review | Selected Finding (`Details`) | identity, status, decision, proof, next | meaningful detail; inline at narrow sizes |
| Prove | Status / NEXT (`Source`) | identity, proof state, stale warning, action | fixed first narrative block |
| Prove | Evidence (`Center`) | observations and source-to-sink evidence | primary list/detail |
| Prove | Proof Ladder (`Findings`) | achieved/missing proof levels | secondary detail if meaningful |
| Prove | Proof / Replay (`Details`) | current verification receipt and replay | third pane only when current; otherwise row/deck |
| Fix | Breakdown (`Source`) | counts, selected finding, report preview | compact context above remediation |
| Fix | Attack Tree (`Center`) | exploit context | optional third surface or focused deck |
| Fix | DFD (`Details`) | data-flow context | optional third surface or focused deck |
| Fix | Remediation (`Findings`) | draft/staged/applied/reverify lifecycle | primary action-bearing surface |

### Phase task hierarchy

| Phase | Primary operator task | Essential before acting | Contextual detail | When pane 2 appears | When pane 3 appears |
|---|---|---|---|---|---|
| Map | judge map readiness and choose the next missing artifact | target/revision/freshness, coverage, NEXT | inventory details, grouped surfaces, zones, hot modules | selected artifact has meaningful detail and post-chrome body can support it | 3 independent surfaces have real data at a wide/tall body; visualization still opens focused |
| Scan | select/inspect an attempt and understand engine outcomes | attempt outcome/freshness, scope, engines, partial acknowledgement, delta, NEXT | receipt, cost, logs, heatmap | a selected engine/attempt has real detail | independent failures or receipt content is actionable, not merely present |
| Review | disposition a finding or open it in Prove | queue row authority/severity/confidence/proof/decision and NEXT | evidence/decision history | a finding is selected | never by default; deeper evidence belongs in Prove/focused views |
| Prove | decide whether evidence justifies verification/action | identity, STATUS, proof, sources, stale warning, NEXT | evidence list, ladder, receipt, replay | evidence or proof detail exists | evidence, ladder, and a current verification receipt are all populated |
| Fix | review lifecycle and explicitly authorize apply/reverify | finding, candidate/lifecycle, diff/touched paths, guardrails, NEXT | attack tree, DFD, report preview | selected patch has meaningful diff/lifecycle detail | one real contextual model adds value on a very wide body |

## 6. Findings

### F01 - Geometry ignores semantic occupancy

- **Severity / operator impact:** High. Empty and one-line surfaces receive the
  same visual authority as the current task, making borders and scanning travel
  dominate phase truth.
- **Phase / fixture / size:** Map, Scan, Review, Fix; empty, sparse, and the
  fully populated reference fixture; most visible at 120x36 and 160x48.
- **Reproduction:** launch the audited binary with
  `KUZUSHI_SKIP_ONBOARDING=1` against the isolated empty target; open Navigate;
  press `1`, `2`, `3`, or `5`; resize to 120x36 or 160x48.
- **Capture:** [empty Map 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/empty/map-120x36.txt),
  [empty Scan 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/empty/scan-160x48.txt),
  [fully populated Scan 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/scan-160x48.txt).
- **Expected hierarchy:** target/reality/NEXT, then one compact truthful
  narrative; add selected detail and a third surface only when data and body
  size justify them.
- **Actual hierarchy:** Map and Scan become unconditional 2x2 grids; Review
  always reserves detail; Fix reserves report, two diagrams, and remediation.
- **Why inefficient:** the eye must cross four regions to discover that three
  are absent, short, or subordinate. Large canvases turn absence into visual
  weight.
- **Ownership:** semantic models already expose `Option`, empty vectors, and
  hints in `ui_view_models/phase_cockpit/mod.rs:65-198`;
  geometry ignores them in `phase_pages/map.rs:18-35`, `scan.rs:23-35`,
  `hunt.rs:14-30`, and `fix.rs:23-90`. Prove is partially better when no
  finding exists (`confirm.rs:23-29,164-177`) but becomes dimension-only once
  a finding is selected (`confirm.rs:225-268`).
- **Recommended behavior:** semantic Sparse/MD/Dense selection. Treat missing
  artifact guidance as a row, not a pane. Cap automatic Dense at three panes.
- **Regression:** table-test visible semantic surface IDs for every phase x
  state x size; assert empty/sparse never allocates a blank region.

This also contradicts the canonical contract: missing Map artifacts should
render one actionable hint and visualization remains contextual
(`docs/design/terminal-cockpit-reference.md:219-221`,
`docs/design/product-flow-design-spec.md:200-202`).

### F02 - Guided attention and focus use different body geometry

- **Severity / operator impact:** High. A foreground question can visually
  compete with a selected body pane while Tab and `Z` target content the body
  no longer renders.
- **Phase / fixture / size:** guided Map and Scan; 40x12 through 160x48,
  strongest at 80x24 and 120x36.
- **Reproduction:** on a durable page, type `scan`; advance to Map Modules or
  Scan Modules; resize the same session; press Tab and `Z` while the card is
  open.
- **Capture:** [Map guided 80x24](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/guided-map/map-guided-80x24.txt),
  [Map guided 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/guided-map/map-guided-120x36.txt),
  [Scan guided 120x36](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/guided-scan/scan-guided-120x36.txt).
- **Expected hierarchy:** card is the sole strong attention/selection region;
  body retains identity, reality, NEXT, and at most a quiet relevant summary.
- **Actual hierarchy:** the card reserves up to 45% of height but the remaining
  body keeps multi-pane borders and its focus accent. Focusability was computed
  from the original full viewport.
- **Why inefficient:** two highlighted regions imply two simultaneous input
  owners. Hidden focus makes navigation appear inert and can scroll or zoom the
  wrong semantic content.
- **Ownership:** card allocation `guided_scan.rs:8-20`; body reduction
  `render_app.rs:55-65`; header/body composition
  `render_workbench_view.rs:35-74`; full-viewport focus
  `phase_pages/mod.rs:25-40` and `sast_task_row.rs:282-293,371-382`.
- **Recommended behavior:** Guided/ResultReady must be an explicit attention
  mode derived after all chrome/card reservations. Expose only visible summary
  surfaces and mute normal body selection.
- **Regression:** live Tab/`Z` traversal for Map and Scan guided cards at every
  requested size; every focusable surface must have a returned rectangle; one
  and only one active accent.

### F03 - Mouse hit-testing describes a retired layout

- **Severity / operator impact:** High. Clicking visible content can focus,
  scroll, or zoom a different semantic pane.
- **Phase / fixture / size:** all phases; every size. Source-confirmed; tmux
  sessions did not enable mouse forwarding, so no misleading synthetic click
  capture is presented.
- **Evidence:** [live Map 120x36 geometry](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/empty/map-120x36.txt)
  establishes the painted regions; `app/state_transitions/text_input.rs:184-323`
  is the hit-test proof. This is deliberately a source-backed interaction
  finding, not a synthetic mouse screenshot.
- **Reproduction:** enable mouse capture, open Map at 120x36, click the visible
  top-right Attack Surface or lower-left Hot Modules region, then use scroll or
  `Z`; repeat on Fix Remediation.
- **Expected hierarchy:** the clicked renderer rectangle owns exact semantic
  focus.
- **Actual hierarchy:** clicks pass full-terminal coordinates to generic
  `FourColumn | ThreeColumn | Stacked | ShortReview` logic with no active page,
  header offset, card height, or rendered rectangle.
- **Why inefficient:** pointer feedback cannot be trusted and diverges further
  as adaptive composition changes.
- **Ownership:** `app/state_transitions/text_input.rs:184-323`; its tests at
  `:407-471` currently enshrine obsolete geometry.
- **Recommended behavior:** one pure presentation plan returns body-coordinate
  `PhaseSurfaceId -> Rect` mappings consumed by renderer and input routing.
- **Regression:** click the center of every returned rectangle at every
  density; header/card/footer clicks must never change pane focus.

### F04 - Compact Map and Prove expose phantom panes

- **Severity / operator impact:** High. Tab changes hidden state or removes the
  visible focus accent, so keyboard navigation appears broken.
- **Phase / fixture / size:** Map and Prove; fully populated reference and
  empty; 40x12 and 60x20.
- **Reproduction:** open Navigate at 40x12; press `1`, then Tab four times;
  press `4`, then Tab four times.
- **Capture:** [compact focus sequence](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/compact-focus/),
  especially `prove-before-tab-40x12.txt` and
  `prove-after-tab-3-40x12.txt`.
- **Expected hierarchy:** Tab cycles only surfaces with visible rectangles.
- **Actual hierarchy:** Map paints one Source-identified combined pane while
  retaining four-pane order; compact Prove paints Source or Source+combined
  Center but retains all four. The Prove accent appears for only one hidden
  focus position in the live sequence.
- **Why inefficient:** operators cannot tell whether input was accepted and
  may act on a hidden scroll/focus target.
- **Ownership:** compact Map `phase_pages/map.rs:72-93`; compact Prove
  `confirm.rs:47-61,164-177`; uncollapsed orders
  `sast_task_row.rs:341-361`.
- **Recommended behavior:** focusable order is an output of the exact layout
  plan, not a parallel phase/viewport approximation.
- **Regression:** Map and Prove counterparts to the existing compact Fix
  phantom-pane test; assert visible focus after every Tab.

### F05 - Fix prioritizes diagrams and makes Remediation non-scrollable

- **Severity / operator impact:** High. The authoritative apply/reverify
  lifecycle is visually subordinate, can clip long touched-path receipts, and
  successful Apply focuses the DFD instead.
- **Phase / fixture / size:** Fix, partial/fully populated reference, 120x36
  and 160x48.
- **Reproduction:** open the fully populated reference Fix (`5`), observe
  initial focus; cycle `Z`
  through Attack Tree, DFD, and Remediation; attempt to scroll a long
  Remediation receipt; complete Apply.
- **Capture:** [Fix 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/fix-160x48.txt),
  [primary focused Attack Tree](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/focused/fix-primary-zoom-120x36.txt),
  [Remediation focused deck](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/focused/fix-remediation-zoom-120x36.txt).
- **Expected hierarchy:** Remediation lifecycle, candidate/diff, authorization,
  touched paths, and exact reverify action precede contextual diagrams.
- **Actual hierarchy:** diagrams receive 52-62% of the body. Remediation maps
  to generic `Findings`, whose scroll offset is hardcoded to zero. Apply sets
  focus to `Details`, which Fix renders as DFD.
- **Why inefficient:** the phase's action and durable proof of mutation are
  literally below contextual explanation and may be unreachable.
- **Ownership:** `phase_pages/fix.rs:53-90,137-219`;
  `sast_task_row.rs:466-507`; `view_hotkey_actions.rs:180-213`;
  `effects.rs:760-793`. This conflicts with
  `terminal-cockpit-reference.md:305-309`.
- **Recommended behavior:** Remediation is Fix primary, Patch/Diff is detail,
  and at most one populated diagram is a dense third surface. Replace generic
  pane behavior with semantic interaction kinds (`Selectable`, `Scrollable`,
  `Diagram`, `Static`).
- **Regression:** long touched-path receipt scrolls in normal and focused
  modes; Apply returns with `REMEDIATION` visibly focused and reverify action
  present.

### F06 - Narrow Review duplicates selected detail

- **Severity / operator impact:** Medium. At 40x12 the queue and duplicate
  detail headings get roughly two rows each, reducing the actionable list.
- **Phase / fixture / size:** Review; empty and fully populated reference;
  40x12 and 60x20.
- **Reproduction:** open Review (`3`) at 40x12, with and without findings.
- **Capture:** [empty Review 40x12](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/empty/review-40x12.txt),
  [fully populated Review 40x12](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/review-40x12.txt).
- **Expected hierarchy:** one queue with a compact inline selected summary; no
  empty second region.
- **Actual hierarchy:** Review always splits list/detail; the queue already
  injects selected detail inline below 72 columns, so the second pane repeats
  the same identity.
- **Why inefficient:** duplicated selection context displaces queue capacity.
- **Ownership:** `phase_pages/hunt.rs:14-30`; inline detail
  `panes/review_queue.rs:114-157`.
- **Recommended behavior:** Sparse Review is one selectable queue plus 2-4
  inline status/NEXT rows. MasterDetail begins only when both sides have useful
  row budgets.
- **Regression:** at 40x12 and 60x20 assert one selection region, visible
  identity/STATUS/NEXT, and a minimum queue row budget.

### F07 - Fix performs blocking filesystem/SQLite work while rendering

- **Severity / operator impact:** Medium performance/architecture risk. Input
  and frame pacing can inherit filesystem/lock latency, and projection can
  initialize workspace state during a nominal render; this audit established
  the synchronous call path but did not measure a user-visible latency spike.
- **Phase / fixture / size:** selected target-backed Fix; all sizes, amplified
  during live 80ms redraws and resizing.
- **Evidence:** [fully populated Fix 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/fix-160x48.txt)
  establishes the selected target-backed render state. The persistence claim
  is source-traced through `render_workbench_view.rs:13-23`,
  `phase_cockpit/phase_bodies.rs:25-70`, and
  `app/services/findings.rs:6-46`; a frame alone cannot prove I/O latency.
- **Reproduction:** open a target-backed Fix with a selected finding; trace
  calls during repeated draw or run a latency test with a cold/locked findings
  DB.
- **Expected hierarchy:** render reads an immutable already-hydrated snapshot;
  no artifact/filesystem discovery.
- **Actual hierarchy:** every Workbench draw rebuilds the phase model;
  `fix_phase_model` calls remediation truth; the service checks filesystem,
  opens SQLite, and performs two queries. Absent DB can fall back to writable
  initialization.
- **Why inefficient:** layout work becomes coupled to blocking persistence and
  the pass criterion "no renderer performs synchronous discovery" is false.
- **Ownership:** `render_workbench_view.rs:13-23`;
  `phase_cockpit/phase_bodies.rs:25-70`;
  `app/services/findings.rs:6-46`; blocking store contract in
  `crates/kuzushi-core/src/findings/persistence/finding_store.rs:3-17`.
- **Recommended behavior:** revision-keyed remediation projection in
  `WorkbenchCache`/`ViewDataState`, refreshed by target/finding/job events.
- **Regression:** target-backed Fix render latency and filesystem non-mutation
  test; fail if render opens SQLite or creates `.kuzushi` state.

### F08 - Workbench rebuilds the same journey projections several times per frame

- **Severity / operator impact:** Medium performance risk; large finding sets
  pay repeated indexing/allocation during every navigation, resize, spinner,
  and guided redraw.
- **Phase / fixture / size:** all target-backed pages; Map is worst.
- **Evidence:** [fully populated Map 160x48](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/settled/map-160x48.txt)
  establishes the target-backed frame; repeated construction is source-traced
  at `phase_cockpit/mod.rs:495-506`, `workbench.rs:161-170,232-270`, and
  `journey.rs:194-248`.
- **Reproduction:** instrument `journey_model` call count for one target-backed
  draw with an explicit page and with derived page; repeat on Map.
- **Expected hierarchy:** one revision-keyed presentation snapshot per state
  change/frame.
- **Actual hierarchy:** phase header, Workbench state, and top bar each build a
  journey; page derivation can add another. Map constructs Home merely to
  extract attack surface.
- **Why inefficient:** repeated work scales with finding/decision count even
  when outputs are discarded.
- **Ownership:** `phase_cockpit/mod.rs:495-506`;
  `workbench.rs:161-170,232-270`; `journey.rs:194-248`;
  `phase_cockpit/map.rs:12-16` and `home_cockpit.rs:102-120`.
- **Recommended behavior:** one `WorkbenchPresentationSnapshot` shares
  journey/header/body/chrome; Map uses a focused attack-surface projection.
- **Regression:** call-count/allocation proxy plus target-backed latency test;
  all projections invalidated by explicit revision keys.

### F09 - Guided card fitting counts Unicode scalars, not terminal columns

- **Severity / operator impact:** Medium accessibility/responsive bug. CJK,
  emoji, and combining input can wrap into unbudgeted rows and clip the selected
  option or footer at 40x12/60x20.
- **Phase / fixture / size:** any guided card; narrow sizes.
- **Evidence:** [guided Scan 40x12](./artifacts/state-responsive-cockpit-audit-2026-07-14/live/guided-scan/scan-guided-40x12.txt)
  establishes the constrained card geometry. The width defect is
  source-confirmed at `guided_scan.rs:265-326`; the current live fixture is
  ASCII-only, so no CJK clipping screenshot is claimed.
- **Reproduction:** use a guided option or Other payload containing CJK, emoji,
  and combining marks at 40x12.
- **Expected hierarchy:** selected option and footer remain in-bounds using
  terminal display width.
- **Actual hierarchy:** local fitting/padding uses `chars().count()` while
  Ratatui wraps by display cells.
- **Why inefficient:** the card budgets fewer terminal cells/rows than the
  renderer consumes, so the active choice or action footer can disappear at
  exactly the sizes where guided interaction needs the clearest hierarchy.
- **Ownership:** `guided_scan.rs:265-326`; correct shared helper already exists
  in `renderer/shared/text/mod.rs:194-209`; current guided tests
  `guided_scan/tests.rs:1-84` are ASCII-only.
- **Recommended behavior:** reuse the shared Unicode-width helpers and delete
  local fit/pad logic.
- **Regression:** CJK, emoji, combining-mark, and narrow-width cases preserve
  focused row and footer.

### F10 - Test and journey coverage preserve one rich layout, not semantic responsiveness

- **Severity / operator impact:** High regression risk. Empty, stale, blocked,
  result-ready, guided, background, click, resize, and target-backed Fix
  failures can all ship while the named 120-buffer contract is green.
- **Phase / fixture / size:** all phases/states/sizes/profiles.
- **Evidence:** the [artifact provenance and verification transcript](./artifacts/state-responsive-cockpit-audit-2026-07-14/README.md)
  records the focused 120-buffer command, while
  `phase_composition_contract/fixture/mod.rs:13-23` proves every cell uses the
  same fixture and `J17-phase-cockpit-reference.journey:9-67` proves the stale
  four-page route.
- **Reproduction:** inspect `PhaseReferenceFixture`, run the green focused test,
  then compare empty/guided live frames; run J17 against current keybindings.
- **Expected hierarchy:** policy assertions cover semantic state and live
  resizing; journeys match Map/Scan/Review/Prove/Fix.
- **Actual hierarchy:** all 120 buffers use one fully populated Live fixture;
  only 30 truecolor goldens exist; two guided tests cover Map only; J17 still
  drives `1=Map, 2=Hunt, 3=Confirm, 4=Fix` and never presses `5`.
- **Why inefficient:** the suite spends substantial snapshot volume proving
  one populated topology while leaving semantic transitions and live resize
  behavior unguarded, so a green contract gives misleading confidence.
- **Ownership:** `phase_composition_contract.rs:113-153`;
  `phase_composition_contract/fixture/mod.rs:13-23`;
  `devex_phase_fixture/mod.rs:11-20,102-107`;
  `renderer/tests.rs:211-268`;
  `scripts/devex/journeys/J17-phase-cockpit-reference.journey:9-67`;
  current keys `view_keybinding_groups.rs:222-234`.
- **Recommended behavior:** three layers: pure plan tables, curated TestBackend
  buffers, and exact-binary live tmux BDD with in-place resize/provenance.
- **Regression:** detailed in section 12 and Plan 040.

## 7. Alternative wireframes

These are presentation contracts, not final typography. They deliberately use
few borders and keep phase/reality/NEXT before details.

### 7.1 Sparse single-column (60x20)

```text
KUZUSHI · MAP · REALITY MAP · ./api@68a1e99
Map ●  Scan ·  Review ·  Prove ·  Fix ·
NEXT build the attack-surface inventory

MAP · CURRENT REVISION
✓ Context          current · 143 files
○ Attack surface   not generated        next
○ Threat model     not generated        build
○ Hot modules      available after Scan
○ DFD              unavailable

Enter inspect · Tab next row · Z focus
────────────────────────────────────────────────────────────
◇ MAP › NAVIGATE
```

At 40x12, keep identity, reality, NEXT, and the first 3-4 priority rows. Do not
spend a body row merely saying "Tab focus."

### 7.2 Master-detail (120x36)

```text
KUZUSHI · REVIEW · target ./api · REALITY REVIEW
NEXT record dispositions for 6 remaining candidates

FINDINGS · 6 NEED ACTION                    SELECTED · F-0001
──────────────────────────────────────────┬──────────────────────────────
> ? CRIT [●●●] 1src CFM  SQL injection   │ STATUS runtime verified
  ? HIGH [●○○] 1src 84%  IDOR            │ DECISION needs review
  ? HIGH [●○○] 1src 79%  template inj.   │ PROOF [●●●] · 1 source
  ? MED  [●○○] 1src 72%  upload type     │
                                           │ src/auth/login.rs:17
                                           │ request_input -> query
                                           │ NEXT patch F-0001
──────────────────────────────────────────┴──────────────────────────────
Enter prove · j/k move · Z focus
```

At narrow widths this becomes one queue with an inline selected summary, not a
vertical queue/detail split.

### 7.3 Dense wide terminal (160x48, maximum three panes)

```text
KUZUSHI · PROVE · F-0001 · REALITY PROVE
STATUS candidate · proof [●●○] · 3 sources · current revision
NEXT verify with the originating detector

EVIDENCE · 50%                     PROOF · 28%          VERIFICATION · 22%
─────────────────────────────────┬────────────────────┬────────────────────
> auth/login.rs:17 · semgrep     │ ● signal captured  │ run verify-91a
  request_input -> query         │ ● path linked      │ detector semgrep
  controlled value reaches SQL   │ ○ exploited       │ current revision
                                  │ current [●●○]      │ 842ms · $0.04
  api/orders.rs:44 · agent       │ 3 sources          │ replay · trace
  tenant boundary crossed        │ proof current      │ result verified
─────────────────────────────────┴────────────────────┴────────────────────
v verify · z attack path · Z focus · Tab pane
```

If current verification data is absent, this collapses to Evidence + Proof.
Width alone never creates the third pane.

## 8. Before/after guided mockups

### 8.1 Map with foreground question

Current 120x36 structure:

```text
HEADER + NEXT
┌ PROJECT CONTEXT ─────┬ ATTACK SURFACE ─────┐
│ background detail    │ background/detail   │
├ HOT MODULES ─────────┼ DFD ────────────────┤
│ background/detail    │ background/detail   │
└──────────────────────┴─────────────────────┘
footer/key hints
┌ MAP · MODULES · STEP 2 OF 3 ───────────────┐
│ active question and choices                │
└────────────────────────────────────────────┘
```

Proposed 120x36:

```text
KUZUSHI · MAP · REALITY REVIEW · ./api
Map ✓  Scan ✓  Review ●  Prove ·  Fix ·
NEXT record dispositions for 6 remaining candidates

MAP SUMMARY · context ✓ · attack surface 2 · hot modules 4 · DFD ready
PLAN DRAFT  · Context + STRIDE · 2 selected



┌ MAP · MODULES · STEP 2 OF 3 ───────────────────────────────────┐
│ Which map modules should Kuzushi run?                          │
│ 1 [ ] Attach reference files                                  │
│ 2 [x] Gather repo context                                     │
│ 3 [ ] Map entry points                                        │
│ 4 [x] Build STRIDE threat model                               │
│ > 9 Continue -> Configure Map                                 │
│ 9/10 · ↑/↓ move · Space toggle · Enter choose · Esc dismiss   │
└────────────────────────────────────────────────────────────────┘
```

Proposed 40x12:

```text
KUZUSHI · MAP · REALITY REVIEW
NEXT review 6 remaining
MAP ✓ context · 2 surfaces · DFD ✓
┌ MAP MODULES · 2/3 ─────────────────┐
│ Which modules should run?          │
│ 8 [ ] Threat intel                 │
│ >9 Continue · 2 selected           │
│ 9/10 · ↑/↓ · Space · Enter         │
└────────────────────────────────────┘
```

### 8.2 Scan with foreground question

Current 120x36 structure:

```text
HEADER + NEXT
┌ SCOPE / PLAN ────────┬ ENGINE OUTCOMES ────┐
├ DELTA ───────────────┼ SCAN RECEIPT ───────┤
└──────────────────────┴─────────────────────┘
footer/key hints
┌ SCAN · MODULES · STEP 1 OF 2 ──────────────┐
│ active question and choices                │
└────────────────────────────────────────────┘
```

Proposed 120x36:

```text
KUZUSHI · SCAN · REALITY REVIEW · ./api
Map ✓  Scan ✓  Review ●  Prove ·  Fix ·
NEXT record dispositions for 6 remaining candidates

SCAN SUMMARY · scan-phase · COMPLETE · 1/1 engine · +6 findings
SELECTED     · sast:scan ✓ · 12s · $0.042



┌ SCAN · MODULES · STEP 1 OF 2 ──────────────────────────────────┐
│ Which scan modules should Kuzushi run?                         │
│ 1 [x] Scan for secrets                                        │
│ 2 [x] Semgrep SAST                                            │
│ 3 [x] CodeQL                                                  │
│ 4 [ ] Agentic SAST                                            │
│ >7 Continue -> Configure Scan                                 │
│ 7/8 · ↑/↓ move · Space toggle · Enter choose · Esc dismiss    │
└────────────────────────────────────────────────────────────────┘
```

Proposed 40x12:

```text
KUZUSHI · SCAN · REALITY REVIEW
NEXT review 6 remaining
SCAN ✓ 1 engine · +6 findings
┌ SCAN MODULES · 1/2 ────────────────┐
│ Which modules should run?          │
│ 6 [ ] Threat-model hunt            │
│ >7 Continue · 3 selected           │
│ 7/8 · ↑/↓ · Space · Enter          │
└────────────────────────────────────┘
```

In both phases, the operator still sees target, selected page, durable reality,
and NEXT. The body is context, not a second interaction region. The card owns
the only selection accent and its selection survives every resize.

## 9. Recommended layout-selection rules

### 9.1 Pure inputs and outputs

Add a pure projection after `PhaseCockpitModel` assembly and before any
phase-specific renderer:

```text
PhasePresentationInputs
  phase
  semantic surface states
  selected semantic surface/item
  exact post-chrome body width/height
  foreground attention kind
  explicit focused surface

PhasePresentationPlan
  density: Sparse | MasterDetail | Dense | Focused | Guided
  primary: PhaseSurfaceId
  visible surfaces: [PhaseSurfaceId]
  focusable order: [PhaseSurfaceId]
  geometry: PhaseSurfaceId -> Rect
  interaction: Static | Selectable | Scrollable | Diagram
  attention owner
  temporary visible fallback focus
```

`PhaseSurfaceId` must be semantic (`MapCoverage`, `ScanOutcomes`,
`ReviewQueue`, `ProveEvidence`, `FixRemediation`), not the current generic
`Source | Center | Findings | Details` alias. Compatibility shims can map old
route state during migration, but renderer and interaction behavior should use
the semantic identity.

### 9.2 Selection algorithm

1. If an explicit focused deck is open and its semantic surface still exists,
   choose `Focused`. `Z` remains the full-frame escape hatch for every retained
   capability.
2. If a foreground question or result-disposition card owns input, choose
   `Guided`. Reserve its rectangle first, then keep identity, reality, NEXT,
   and at most three quiet summary rows. Remove hidden focus/hit targets.
3. Classify surfaces from semantic state. A real artifact/list/action and an
   actionable blocked or stale explanation are meaningful. An empty heading or
   one generic hint is a row, not a meaningful pane.
4. Choose `Sparse` when there are zero/one meaningful surfaces, width is below
   50, or the exact body height is below 14.
5. Choose `MasterDetail` when exactly two surfaces are meaningful, or when a
   selected item has meaningful detail and the post-chrome body is at least
   approximately 78x14.
6. Choose `Dense` only when at least three independently useful surfaces exist
   and the post-chrome body is approximately 120x24 or larger. Cap at three
   automatic panes.
7. A third pane needs its own task or at least five independent useful rows; a
   populated visualization also needs enough geometry to remain legible.
8. Stale, blocked, missing, and unavailable are semantic tones/statuses, not
   extra pane triggers.
9. Result-ready follows Guided attention rules. Background waiting input does
   not change density or steal focus, but `WAITING INPUT`/`1 INPUT` is a
   priority atom that must survive 40x12.
10. Preserve selection by semantic identity and scroll per semantic surface.
    If resize hides the selected surface, use an ephemeral visible fallback;
    restoring size or leaving Guided restores the prior selection and scroll.
11. Rendering, keyboard focus, mouse hit-testing, scrolling, and zoom must
    consume the same returned plan. No parallel geometry heuristics.
12. Plain output remains a complete linear reading order. It may ignore visual
    density while preserving the same status, labels, and exact actions.

The numeric thresholds above are starting fixtures, not a substitute for
semantic policy. The planner receives the body after phase header, footer,
question/result card, and any visible chrome have been reserved.

## 10. Accessibility and no-color analysis

### What currently works

- All audited pages retain phase labels, glyphs, textual status, and selection
  markers without color. The no-color Review 40x12 frame remains understandable
  through `▸`, severity letters, proof mini-meter, titles, and labels.
- Live ANSI-256 Map emitted indexed color and no RGB escape sequences.
- Live high-contrast Map used the high-contrast semantic theme and disabled
  cinematic competition.
- Live `NO_COLOR=1` Map emitted no RGB or indexed-color SGR, only textual
  content and modifiers.
- Plain output linearizes the queue before selected detail and uses ASCII
  markers, so its reading order is coherent.
- Theme policy itself is sound: high-contrast/no-color strengthen text and
  disable decorative cinematic backgrounds (`theme/mod.rs:43-125,183-218,
  289-308`; `theme/cinematic.rs:66-83`).

### Remaining accessibility risks

- At 40x12 background Review retains generic `LIVE` but loses the more
  important `1 INPUT` footer atom. Waiting operator input must outrank generic
  activity state.
- Guided body focus and card focus create two apparent attention owners on
  wide screens. Color cannot be the only distinction; the body selection band
  should be absent/muted during Guided.
- Empty pane borders are contrast-heavy in every profile, so high contrast can
  amplify the wrong hierarchy even though the palette itself is correct.
- Unicode display-width handling in guided options can clip the selected row.
- Adaptive layouts must retain a non-color selection marker, full selected
  label, phase/reality wording, proof meter, and exact NEXT action at every
  breakpoint.

Required accessibility assertions:

- exactly one selection/attention owner in Guided and ResultReady;
- selected semantic identity remains visible in no-color mode;
- `WAITING INPUT` survives 40x12 background operation;
- all warning/failure/stale/proof meanings have a word or glyph;
- CJK/emoji/combining labels stay inside card rectangles;
- focused decks restore the originating phase, semantic surface, selection,
  scroll, and input mode.

## 11. Performance implications

Adaptive layout can reduce work, but only if it changes the projection/render
boundary rather than merely hiding already-built lines.

### Required performance changes

1. **No synchronous persistence in render.** Move Fix remediation hydration out
   of `fix_phase_model` and into a revision-keyed cache refreshed at target,
   finding, patch, apply, reverify, and job-event boundaries.
2. **One presentation snapshot per frame/state revision.** Share journey,
   header, body, and chrome instead of rebuilding the review-state index three
   to five times.
3. **Do not build hidden heavy surfaces.** The plan chooses visible surfaces
   before diagram line generation. A hidden DFD/attack tree should retain a
   cheap readiness summary and build its full projection only for Dense or a
   focused deck.
4. **Keep the planner O(surface count).** It consumes already-hydrated semantic
   state, performs no filesystem/network/model/process work, and allocates at
   most the small fixed surface list.
5. **Window before formatting.** Long lists/receipts remain windowed by semantic
   selection and scroll before styled lines are constructed.

### Performance gates

- target-backed Fix render cannot create/open `.kuzushi` state;
- one draw performs one journey/index construction;
- hidden diagrams do not build full geometry;
- resize and guided-card redraw meet the existing frame-latency budget with a
  dense finding fixture;
- cache keys include target identity, revision, finding fingerprint/generation,
  patch/application identity, and presentation revision so speed never hides
  stale truth.

## 12. Prioritized implementation plan

No implementation is authorized by this audit. If the mockups and direction are
approved, execute these self-contained plans in order:

| Order | Plan | Priority | Effort | Purpose | Approval boundary |
|---:|---|---:|---:|---|---|
| 1 | [037](./037-state-responsive-cockpit-presentation-policy.md) | P1 | L | pure semantic plan, surface IDs, shared focus/scroll/mouse geometry | approve semantic policy and compatibility approach |
| 2 | [038](./038-adaptive-phase-layouts-and-guided-attention.md) | P1 | L | phase-specific adaptive renderers and Guided/ResultReady hierarchy | approve wireframes and density thresholds |
| 3 | [039](./039-cockpit-presentation-cache.md) | P1 | M | remove render-path SQLite/repeated journey work | approve cache/invalidation boundary |
| 4 | [040](./040-cockpit-state-matrix-and-live-journeys.md) | P1 | L | semantic fixture matrix, curated snapshots, live resize/profile journeys, J17 repair | approve evidence volume and golden strategy |

Plans 038 and 039 may proceed in parallel after Plan 037 if separate executors
own renderer and projection-cache paths. Plan 040 lands after both so its live
goldens describe the final behavior. Each functional plan includes focused
tests; Plan 040 adds the exhaustive cross-state proof.

## 13. Snapshot, unit, and live-terminal test plan

### Layer 1: pure policy unit tests

Create explicit semantic fixtures for:

```text
Empty | Sparse | Partial | Dense | Stale | Blocked |
ResultReady | Guided | Background
```

For every phase x state x requested size, assert:

- density;
- primary semantic surface;
- visible/focusable surface identities and order;
- exactly one attention owner;
- every focusable surface has a nonempty rectangle;
- no rectangles overlap header, card, or footer;
- at most three automatic Dense surfaces;
- semantic selection and hidden-focus fallback behavior.

These are table assertions, not 225 brittle snapshots.

### Layer 2: TestBackend contracts and curated goldens

- Retain the current six-size/four-profile rich matrix.
- Add all five sizes for Empty, Dense, and Guided; add 80x24/120x36 for Sparse,
  Partial, Stale, Blocked, ResultReady, and Background.
- Keep goldens for representative structural changes only: all phases at
  40x12, 80x24, 120x36, 160x48 in truecolor; pairwise ANSI-256,
  high-contrast, and no-color states rather than snapshotting every cell.
- Assert semantics separately from glyph-perfect snapshots.
- Add long remediation receipts, empty Review selection, missing Prove proof,
  stale proof, partial Scan acknowledgement, failed explicit-model run, and
  background waiting-input priority.
- Add Unicode guided options and Other input.

### Layer 3: exact-binary live tmux BDD

For each phase:

1. launch the exact `KUZUSHI_BIN` in a fresh tmux alternate screen;
2. record binary version, HEAD, dirty state, target identity, profile, initial
   size, `alternate_on`, and actual pane dimensions;
3. select a non-first item, scroll each visible semantic surface, focus a
   secondary surface, and open `Z`;
4. resize the same session 160x48 -> 120x36 -> 80x24 -> 60x20 -> 40x12 ->
   160x48;
5. assert semantic selection identity, scroll, stored focus, visible fallback,
   and focused-deck restoration at every step;
6. repeat with Map and Scan Guided, Scan ResultReady, one background question,
   and one explicit-model blocked run;
7. capture text with `-p` and ANSI with `-e -p` only while
   `alternate_on=1`.

Profile coverage:

- truecolor: all phases at all five sizes;
- ANSI-256: every phase at 80x24/120x36 plus compact Review/Guided;
- high contrast and no color: every phase pairwise across 40x12, 80x24,
  160x48;
- plain: complete reading order and exact action commands.

### Journey/harness corrections

- Replace J17's Map/Hunt/Confirm/Fix keys with all five canonical pages.
- Add a live-only snapshot directive that fails unless `alternate_on=1`.
- Add `--artifact-root` / `KUZUSHI_DEVEX_ARTIFACT_ROOT` so read-only audits can
  isolate evidence.
- Record provenance alongside every capture and distinguish explicit saved-
  alternate-screen recovery from live frames.
- Never treat a stale stored J17 run as current evidence.

### Verification gates after implementation

```text
cargo fmt --all -- --check
cargo test -p kuzushi-tui --offline
cargo test -p kuzushi-bdd-tui --offline
cargo clippy --offline --workspace --all-targets -- -D warnings
pnpm quality:crap-risk
pnpm check:docs
```

The new/modified Kuzushi-owned functions must remain below the repository CRAP
risk threshold and use the shared pure policy rather than duplicating branches
across five renderers.

## 14. Explicit unresolved design decisions

These require operator/design approval before implementation:

1. **Dense breakpoint:** confirm post-chrome body threshold (proposal:
   approximately 120x24), including whether height or terminal aspect ratio can
   veto a third pane.
2. **Dense geometry:** choose three columns versus master-detail plus a lower
   rail per phase. The proposal favors task-specific geometry, not one global
   three-column template.
3. **Map default selection:** decide whether the first missing actionable
   artifact, current selected row, or most severe populated surface drives
   detail.
4. **Review wide mode:** confirm that Review remains two-pane even at 160x48;
   deeper evidence moves to Prove/focused views.
5. **Fix hierarchy:** approve Remediation as the default/return focus and at
   most one contextual diagram in automatic Dense mode.
6. **ResultReady style:** use the same quiet-body policy as Guided or an even
   more compact receipt-only body.
7. **Background attention:** decide the exact 40x12 atom (`1 INPUT`,
   `WAITING INPUT`, or both) that outranks generic `LIVE`.
8. **Semantic route migration:** retain generic `WorkbenchPane` as an internal
   compatibility shim for one release or migrate persisted route/focus state in
   one cutover.
9. **Focused disappearance:** if a focused semantic surface becomes empty
   after refresh, close to origin with an explanation or keep an explicit empty
   focused deck.
10. **Plain output:** always emit complete reading order (recommended) or mirror
    visual disclosure while offering a `--verbose` analogue.
11. **Stale truth source:** identify the authoritative target/revision binding
    for Map context and make stale semantic state deterministic before adding
    stale visual goldens.
12. **Mouse support:** keep it first-class and move it onto returned rectangles
    (recommended), or explicitly deprecate it instead of preserving a false hit
    map.

## 15. Proposed-design pass criteria

| Criterion | Current binary | Proposed hybrid |
|---|---|---|
| Empty panels do not reserve large regions | Fail | Pass by Sparse rows |
| Existing views remain reachable | Pass through `Z`/`z` | Preserve and test |
| Sparse pages compact and line-based | Partial at 40/60 | Pass all sizes/states |
| Panes require meaningful data | Fail | Semantic threshold |
| Primary task and NEXT immediate | Mostly pass | Preserve as invariant |
| Guided card owns attention | Partial/Fail wide | Explicit Guided plan |
| Mode and durable reality visible | Pass | Preserve |
| Navigation never forges reality | Pass | Preserve |
| Resize preserves selection/scroll/focus | Selection observed; focus contract untested/broken | Semantic identity + live loop |
| No-color hierarchy uses labels/glyphs | Pass baseline | Preserve + one-owner tests |
| 40x12 usable | Mostly pass; blocked reason/background input can disappear | Priority atoms + Sparse/Guided |
| Dense 160x48 uses space without empty dashboard | Fail Map/Scan/Fix | At most three real surfaces |
| Policy pure/testable outside terminal | Fail; renderer-local heuristics | Pure plan tables |
| No synchronous discovery in renderer | Fail target-backed Fix | Cached projection only |

## 16. Direct recommendation

**Use a hybrid.** Replace the automatic four-quadrant default with a pure
adaptive `Sparse | MasterDetail | Dense | Focused | Guided` presentation policy.
Retain every existing panel as a semantic surface and full-frame focused deck,
and permit a third pane only when real content plus the post-chrome terminal
body justify it. Do not implement until the wireframes, Fix hierarchy, Dense
breakpoint, and semantic-route migration above are approved.
