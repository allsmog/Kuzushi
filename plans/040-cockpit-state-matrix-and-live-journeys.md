# Plan 040: Prove adaptive cockpit behavior across semantic states and live terminals

> **Executor instructions**: Begin after Plans 038 and 039 are complete. This
> plan validates approved behavior; do not update goldens to bless unexplained
> output. Preserve the dirty tree, run exact provenance checks, and update Plan
> 040 in `plans/README.md` when complete.
>
> **Drift check (run first)**: inspect committed, dirty, and untracked changes
> across every fixture, snapshot, input test, BDD, journey, and provenance file
> this plan may touch.

```zsh
drift_paths=(
  crates/kuzushi-tui/src/renderer/phase_composition_contract.rs
  crates/kuzushi-tui/src/renderer/phase_composition_contract
  crates/kuzushi-tui/src/renderer/snapshots/phase_cockpit
  crates/kuzushi-tui/src/renderer/tests.rs
  crates/kuzushi-tui/src/app/state_transitions
  crates/kuzushi-tui/src/app/devex_phase_fixture
  crates/kuzushi-bdd-tui
  scripts/devex
  docs/devex
)
git diff --stat 76974ccf5..HEAD -- "${drift_paths[@]}"
git diff --stat -- "${drift_paths[@]}"
git status --short -- "${drift_paths[@]}"
```

Any new semantic fixture or live-capture harness work must be reconciled before
execution; never overwrite an unexplained golden or journey change.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: LOW
- **Depends on**: Plans 038 and 039
- **Category**: tests / DX / docs
- **Planned at**: commit `76974ccf5`, 2026-07-14

## Why this matters

The current test name suggests 120 responsive cases, but all use one fully
populated fixture. J17 still drives four retired Map/Hunt/Confirm/Fix pages.
Adaptive layout needs semantic-state assertions, curated—not explosive—goldens,
and live exact-binary resize journeys that prove selection, scroll, focus,
attention, and terminal-profile behavior.

## Current state

- `renderer/phase_composition_contract.rs:113-153` covers five phases x six
  sizes x four profiles and 30 truecolor goldens.
- `phase_composition_contract/fixture/mod.rs:13-23` always returns one rich
  Live fixture.
- `devex_phase_fixture/mod.rs:11-20,102-107` supports only Live/Settled.
- `renderer/tests.rs:211-268` covers guided Map at 120x36/40x12 without focus
  parity.
- `kuzushi-bdd-tui/features/cockpit_five_phase_modes.feature` cycles live pages
  but never resizes an already-running page through the full matrix.
- `scripts/devex/journeys/J17-phase-cockpit-reference.journey:9-67` expects
  Map/Hunt/Confirm/Fix and keys 1-4; live `WorkbenchPage::ALL` has five pages.
- `scripts/devex/lib.sh` captures current alternate screen correctly when live,
  but generic journeys can fall back to saved screen and do not persist full
  provenance per capture.
- Journey artifacts are hardcoded under `scripts/devex/artifacts` rather than
  accepting an audit artifact root.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Policy matrix | `cargo test -p kuzushi-tui phase_presentation_matrix --offline` | pass |
| Renderer contract | `cargo test -p kuzushi-tui phase_composition_contract --offline` | pass |
| Build live binary | `cargo build -p kuzushi-cli --offline` | `target/debug/kuzushi` rebuilt from the reviewed tree |
| BDD | `KUZUSHI_BIN="$PWD/target/debug/kuzushi" cargo test -p kuzushi-bdd-tui --offline` | pass using exact binary |
| Full TUI | `cargo test -p kuzushi-tui --offline` | pass |
| Docs | `pnpm check:docs` | pass |
| CRAP | `pnpm quality:crap-risk` | pass |

## Scope

**In scope**:

- `crates/kuzushi-tui/src/renderer/phase_composition_contract.rs`
- `crates/kuzushi-tui/src/renderer/phase_composition_contract/**`
- curated `renderer/snapshots/phase_cockpit/**`
- focused renderer/input tests
- `crates/kuzushi-bdd-tui/features/**` and exact supporting steps/harness code
- `scripts/devex/journeys/J17-phase-cockpit-reference.journey`
- profile journey(s) such as J15 where phase coverage belongs
- `scripts/devex/run-journey.sh`, `scripts/devex/lib.sh`, and journey docs only
  for live/saved capture distinction, artifact root, and provenance

**Out of scope**:

- changing approved layout behavior to satisfy old goldens;
- provider/model calls or paid benchmarks;
- product execution behavior;
- recording secrets or operator home paths in fixtures.

## Git workflow

Stay on the active branch unless directed. Goldens are intentional changes and
must be reviewed by semantic state, not bulk-accepted. No commit/push without
authorization.

## Steps

### Step 1: Add an explicit semantic fixture enum

Create deterministic, test-only fixtures:

```text
Empty, Sparse, Partial, Dense, Stale, Blocked,
ResultReady, Guided, Background
```

Construct already-hydrated phase models; do not reach filesystem or line-count
render output to infer state. Include long remediation, missing/current/stale
proof, partial Scan acknowledgement, waiting input, and Unicode card content.

**Verify**: fixture tests name each populated/missing semantic surface exactly.

### Step 2: Add exhaustive pure policy tables

Cross every phase x semantic state x 40x12/60x20/80x24/120x36/160x48. Assert
density, primary, visible/focusable order, one attention owner, in-bounds
rectangles, and selection fallback/restore. Do not create 225 goldens.

**Verify**: `phase_presentation_matrix` passes and reports the exact cell on a
failure.

### Step 3: Curate renderer/profile goldens

Keep current rich coverage. Add all sizes for Empty, Dense, Guided and selected
80x24/120x36 cases for other states. Cover truecolor structurally; pairwise
ANSI-256/high-contrast/no-color cells. Assert no RGB under ANSI-256, no color
SGR under `NO_COLOR`, and visible glyph/label selection.

Review each changed golden for target/reality/NEXT, semantic surfaces, and one
attention owner before accepting.

**Verify**: renderer contract passes; snapshot count is documented and bounded.

### Step 4: Add in-place live resize and focused-navigation BDD

Launch the exact `KUZUSHI_BIN` in tmux, require `alternate_on=1`, select a
non-first item, scroll/focus/zoom, then resize one process:

```text
160x48 -> 120x36 -> 80x24 -> 60x20 -> 40x12 -> 160x48
```

Repeat all five phases; Guided Map/Scan; Scan ResultReady; one background
question; one explicit-model blocked run. Assert semantic selection, scroll,
stored focus, visible fallback, focused-deck origin, and no focus theft.

**Verify**: BDD passes twice with exact binary path and no saved-screen
fallback.

### Step 5: Repair J17 and profile journeys

J17 must drive keys 1-5 and expect Map/Scan/Review/Prove/Fix. Update docs to
describe the same journey. Extend live profile coverage to durable phase pages,
including no-color and 40x12 Guided/Review.

**Verify**: journey runner produces current live frames and expected canonical
page labels at every checkpoint.

### Step 6: Make capture provenance explicit

Add a live-only snapshot directive that fails unless `alternate_on=1`, an
explicit saved-screen directive, and configurable artifact root. Per capture,
record binary version/path/hash or mtime, HEAD/dirty state, target, profile,
requested/actual dimensions, tmux version, alternate-screen flag, timestamp,
and journey step.

**Verify**: a deliberate post-exit live snapshot fails; explicit saved capture
succeeds and is labeled; custom artifact root leaves `scripts/devex/artifacts`
untouched.

### Step 7: Run the complete gates and review artifact volume

Run every command in the table. Confirm no provider calls, secrets, temporary
homes, or fixture databases are committed. Ensure the final matrix remains
fast enough for CI and goldens remain reviewable.

## Test plan

- 225 pure policy cells plus invariants.
- Curated structural buffers across state/profile/size.
- Unicode/card/no-color assertions.
- Live in-place resize/focus/scroll/zoom restoration for all phases.
- Guided, ResultReady, Background, Blocked live attention cases.
- Capture provenance positive/negative cases.
- J17 exact five-page route and current docs.

## Done criteria

- [ ] Every requested semantic state has a deterministic fixture.
- [ ] Every phase/state/size has a pure policy assertion.
- [ ] Curated profile goldens are bounded and reviewed.
- [ ] Exact-binary live resize preserves selection/scroll/focus.
- [ ] Guided/result cards own one attention region.
- [ ] J17 matches five canonical pages.
- [ ] Live captures cannot silently become saved-screen evidence.
- [ ] Artifact root is configurable and provenance complete.
- [ ] All command-table gates pass without provider calls.

## STOP conditions

- Plans 038/039 are incomplete or behavior differs from approved mockups.
- A semantic state cannot be built without external/provider effects; use an
  inert hydrated fixture and report the gap.
- Snapshot volume becomes unreviewable; retain semantic assertions and reduce
  goldens rather than skipping states.
- Live harness cannot prove exact binary/alternate-screen provenance.
- Any verification fails twice after bounded correction.

## Maintenance notes

New states belong first in the pure fixture/policy matrix. Add a golden only
when pixel/character geometry itself is a contract, and a live journey only
when PTY/input/resize behavior cannot be proven off-screen.
