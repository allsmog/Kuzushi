# Plan 039: Cache cockpit projections outside the render loop

> **Executor instructions**: Begin after Plan 037 defines semantic presentation
> inputs. Preserve the dirty tree and never weaken freshness or durable truth
> for speed. Run every gate. Update Plan 039 in `plans/README.md` when complete.
>
> **Drift check (run first)**: inspect committed, dirty, and untracked changes
> across the cache, hydration, invalidation, projection, and render owners.

```zsh
drift_paths=(
  crates/kuzushi-tui/src/app/domain_cache.rs
  crates/kuzushi-tui/src/app/services/findings.rs
  crates/kuzushi-tui/src/app/view_state/workbench_cache.rs
  crates/kuzushi-tui/src/app/view_state/workbench_cache
  crates/kuzushi-tui/src/app/view_hydration
  crates/kuzushi-tui/src/app/tool_runner/run_tool/events_and_results.rs
  crates/kuzushi-tui/src/app/scan/start_scan/scan_success_events.rs
  crates/kuzushi-tui/src/app/command_router/command_effects.rs
  crates/kuzushi-tui/src/app/effects.rs
  crates/kuzushi-tui/src/app/session/handle_context_command/navigation_target_story.rs
  crates/kuzushi-tui/src/ui_view_models/workbench.rs
  crates/kuzushi-tui/src/ui_view_models/phase_cockpit
  crates/kuzushi-tui/src/ui_view_models/home_cockpit.rs
  crates/kuzushi-tui/src/renderer/views/workbench/render_workbench_view.rs
)
git diff --stat 76974ccf5..HEAD -- "${drift_paths[@]}"
git diff --stat -- "${drift_paths[@]}"
git status --short -- "${drift_paths[@]}"
```

Any overlapping cache-key, view-hydration, or event-invalidation refactor is a
STOP condition until its freshness contract is reconciled here.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: Plan 037
- **Category**: performance / architecture
- **Planned at**: commit `76974ccf5`, 2026-07-14

## Why this matters

Selected target-backed Fix can open SQLite and execute queries during every
paint. Workbench also rebuilds the same journey/review index three to five
times per frame. Adaptive rendering must not merely hide lines after paying
these costs; it needs an immutable, freshness-keyed presentation snapshot so
input remains responsive without lying about current target/revision truth.

## Current state

- `render_workbench_view.rs:13-23` rebuilds the phase model every draw.
- `phase_cockpit/phase_bodies.rs:25-70` synchronously loads remediation truth.
- `app/services/findings.rs:6-46` checks filesystem, opens SQLite, and queries
  patch/application history; absent DB may use writable initialization.
- `phase_cockpit/mod.rs:495-506` builds journey for the phase header.
- `ui_view_models/workbench.rs:161-170,232-270` builds it again for page/state
  and top bar.
- `ui_view_models/journey.rs:194-248` constructs an effective review-state
  index across findings/decisions.
- `phase_cockpit/map.rs:12-16` constructs Home to extract attack surface.
- The existing cache is `app/view_state/workbench_cache.rs:47-82`, stored by
  `DomainCache` in `app/domain_cache.rs`; hydrated cache entries use
  `ViewDataState::{NotRequested,Loading,Ready}` in
  `app/view_hydration/mod.rs:24-36` and are applied in
  `workbench_cache/hydration_state.rs`.
- Existing view-model fragments and revision keys live in
  `workbench_cache/view_model_fragments.rs`; extend that cache instead of
  inventing a second presentation cache.
- Target revision switch already cancels hydration and replaces
  `WorkbenchCache` in
  `session/handle_context_command/navigation_target_story.rs:396-397`.
- Scan and tool terminal effects already invalidate hydration, run summaries,
  and workspace files in `scan/start_scan/scan_success_events.rs:360-363` and
  `tool_runner/run_tool/events_and_results.rs:520-523`.
- `WorkbenchCache::invalidate_run_summaries`,
  `invalidate_workspace_files`, `invalidate_state_artifact_paths`, and
  `invalidate_run_summary_dependents` are the existing invalidation owners at
  `workbench_cache.rs:217-218,328-368,391-460`.
- `effects.rs:760-793` persists successful patch application and changes Fix
  focus but currently performs no remediation-projection invalidation.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Format | `cargo fmt --all -- --check` | pass |
| Cache tests | `cargo test -p kuzushi-tui workbench_presentation_cache --offline` | pass |
| Latency tests | `cargo test -p kuzushi-tui workbench_render_latency --offline` | pass |
| Full TUI | `cargo test -p kuzushi-tui --offline` | pass |
| Clippy | `cargo clippy --offline -p kuzushi-tui --all-targets -- -D warnings` | pass |
| CRAP | `pnpm quality:crap-risk` | pass |

## Scope

**In scope**:

- `crates/kuzushi-tui/src/app/domain_cache.rs` only where it owns
  `WorkbenchCache`
- `crates/kuzushi-tui/src/app/view_state/workbench_cache.rs`
- `crates/kuzushi-tui/src/app/view_state/workbench_cache/cache_entries.rs`
- `crates/kuzushi-tui/src/app/view_state/workbench_cache/hydration_state.rs`
- `crates/kuzushi-tui/src/app/view_state/workbench_cache/view_model_fragments.rs`
- `crates/kuzushi-tui/src/app/view_state/workbench_cache/remediation_projection.rs`
  (new, with focused tests in the existing cache test module)
- `crates/kuzushi-tui/src/app/view_hydration/{mod,requests,reader}.rs` and
  hydration tests for the new key/value
- `crates/kuzushi-tui/src/app/services/findings.rs`
- `crates/kuzushi-tui/src/app/tool_runner/run_tool/events_and_results.rs`
- `crates/kuzushi-tui/src/app/scan/start_scan/scan_success_events.rs`
- `crates/kuzushi-tui/src/app/effects.rs`
- `crates/kuzushi-tui/src/app/session/handle_context_command/navigation_target_story.rs`
- `crates/kuzushi-tui/src/app/command_router/command_effects.rs` only if the
  phase-picker refresh must invalidate the shared snapshot
- `crates/kuzushi-tui/src/ui_view_models/workbench.rs`
- `crates/kuzushi-tui/src/ui_view_models/phase_cockpit/{mod,map,phase_bodies}.rs`
- `crates/kuzushi-tui/src/ui_view_models/home_cockpit.rs`
- `crates/kuzushi-tui/src/renderer/views/workbench/render_workbench_view.rs`
- focused cache/latency/non-mutation tests

**Out of scope**:

- changing FindingStore schema or durable artifacts;
- weakening current-revision/generation checks;
- hiding loading/error states;
- layout visuals (Plan 038);
- full fixture/journey matrix (Plan 040).

## Git workflow

Stay on the active branch unless directed otherwise. Preserve all user-owned
hunks. No commit/push without authorization.

## Steps

### Step 1: Define explicit presentation cache keys and states

Add `ViewHydrationKey::FindingPatchTruth { fingerprint, target_revision }` and
a matching `FindingPatchTruthState::{Ready, Missing, Failed}` value in
`app/view_hydration/mod.rs`. Add a keyed entry in the new
`workbench_cache/remediation_projection.rs`; its full key is target path,
target revision, and finding fingerprint/generation. The ready value retains
patch-run/application identity, diff hash, and lifecycle `updated_at`, so a
later result cannot masquerade as the current application.

In `workbench_cache/view_model_fragments.rs`, add one cached expensive
journey/review projection keyed by `findings_revision`,
`review_decisions_revision`, target base/revision, active scope/filter, and the
engagement/presentation revision. Build the cheap page/focus-specific
`WorkbenchPresentationSnapshot` from that projection once per draw; do not
cache terminal rectangles or selection styling.

Do not key solely by path or selected row index. Do not silently reuse stale
data after target/revision changes.

**Verify**: unit tests prove key changes for each truth boundary and stable keys
for pure view/page/focus changes.

### Step 2: Hydrate remediation outside paint

In `view_hydration/requests.rs::append_workbench_keys`, request
`FindingPatchTruth` only for an active Fix selection. In
`view_hydration/reader.rs`, call a read-only findings service that returns
`Missing` when the DB path does not exist; remove the current writable
`FindingStore::open(path)` fallback from this read path. Apply the result in
`workbench_cache/hydration_state.rs` and expose
`WorkbenchCache::cached_finding_patch_truth(...) -> ViewDataState<_>`.

`phase_cockpit/phase_bodies.rs::remediation_lifecycle_model` must consume only
that state: `NotRequested/Loading` renders loading, `Missing` renders the
truthful not-drafted/no-receipt state, `Failed` renders the error, and `Ready`
maps the receipt. It must never call `finding_patch_truth_for_target` or open a
store during paint.

**Verify**: a render-only test with a nonexistent `.kuzushi` path creates no
files and performs no store open; event tests refresh after lifecycle changes.

### Step 3: Build one shared Workbench presentation snapshot

Extend `workbench_cache/view_model_fragments.rs` with explicit
`WorkbenchProjectionCacheKey`, cached review index/journey inputs, and
`invalidate_workbench_projection`. Construct one
`WorkbenchPresentationSnapshot` at the start of
`render_workbench_view.rs::render_workbench_view` and pass its page, header,
body, and chrome projections downward. Remove unused top-bar construction for
target-backed phase rendering. Extract a focused Map attack-surface projection
instead of building all Home cards.

**Verify**: instrumentation/counter test observes one journey/index build for
explicit and derived page draws; Map does not construct discarded Home cards.

### Step 4: Skip hidden heavy visual projections

Use Plan 037 visibility to avoid full DFD/attack-tree line/geometry generation
when a readiness row is sufficient. Focused and Dense entry materialize the
real projection from already-hydrated data; no I/O occurs in this choice.

**Verify**: counters prove hidden diagrams do not build geometry and focused
entry builds exactly once per relevant revision.

### Step 5: Prove invalidation and latency

Wire and test these exact invalidation boundaries:

- target/revision switch keeps the full `WorkbenchCache::default()` reset in
  `navigation_target_story.rs:396-397`;
- scan terminal and tool terminal events call
  `invalidate_workbench_projection` plus
  `invalidate_finding_patch_truth` beside the existing calls at
  `scan_success_events.rs:360-363` and `events_and_results.rs:520-523`;
- `effects.rs::finish_reviewed_patch_apply` invalidates the selected
  fingerprint after the lifecycle receipt is persisted and before Fix is
  rendered;
- patch creation, reverify terminal completion, findings reload, and any state
  artifact path flagged as findings-changed route through the same named cache
  methods, not bespoke field mutation;
- page/focus/resize changes do not invalidate domain projections, while a
  selection change naturally requests the new fingerprint key.

Test target switch, revision change, finding selection/generation, patch
creation, apply, reverify terminal event, findings reload, and background run
completion. Loading/error state must be visible rather than falling back to old
truth.

Run all command-table gates.

## Test plan

- Key equality/inequality for every domain boundary.
- No filesystem mutation/open during render.
- Correct invalidation on lifecycle events and target switch.
- One journey/review-index construction per frame/revision.
- Dense findings + selected Fix latency under existing threshold.
- Hidden versus focused diagram construction counts.
- Error/loading projections remain explicit and no silent stale reuse occurs.

## Done criteria

- [ ] No render path opens FindingStore or discovers artifacts synchronously.
- [ ] One shared Workbench snapshot supplies journey/header/body/chrome.
- [ ] Cache keys bind all target/revision/finding/lifecycle truth.
- [ ] Hidden heavy surfaces are not fully built.
- [ ] Loading/error truth is visible.
- [ ] Latency, full TUI, Clippy, formatting, and CRAP gates pass.

## STOP conditions

- Correct invalidation requires weakening or guessing durable identity.
- A cache can show stale remediation after apply/reverify/target switch.
- The only available refresh boundary polls the filesystem from render.
- An overlapping user-owned domain-cache refactor conflicts with this shape.
- Any gate fails twice after a bounded correction.

## Maintenance notes

Every new projection cache key must name its truth/invalidation boundary.
Reviewers should reject time-based freshness or silent fallback to prior data.
