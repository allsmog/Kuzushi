# Plan 028: Make completion invalidation semantic and file hydration finite

> Executor: preserve completion ordering, target-generation isolation, async
> rendering, and the 5,000-candidate product cap. Incomplete discovery must be
> visible rather than presented as a complete workspace inventory.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: TUI performance/cancellation
- **Depends on**: Plan 013
- **Planned at**: commit `775a4134f2cb`, Cycle 6

## Why this matters

Generic `scan_mut()` and `activity_mut()` access increments the same generation
used by completion previews, so ordinary scan-stage progress reranks thousands
of unchanged file candidates. File discovery also collects and sorts every
entry in a directory before applying the 5,000-file result cap; a stale walk of
a huge target can retain one of only two hydration workers after a target
switch.

## Steps

1. Remove completion-generation side effects from generic mutable accessors.
   Invalidate live-run completions only when the effective scan, activity, or
   tool run ID changes; invalidate file/finding sources only when their cached
   value or target generation changes.
2. Put explicit entry-visit, retained-result, depth, and path-byte budgets on
   file discovery before collection/sort allocation. Keep a bounded retained
   set with stable output ordering and return explicit truncation metadata when
   the visit budget prevents a complete inventory.
3. Give hydration requests a cancellation/generation token observed between
   directory chunks. Target switching and superseding file hydration must free
   stale worker capacity promptly, and a stale result must never overwrite the
   current cache.
4. Surface truncated file suggestions in the picker/completion state with a
   useful next step; do not silently imply that no other files exist.

## Verification

- With `attach src/file-4999` active, multiple scan-stage/activity mutations
  that retain the same live IDs cause zero new provider reads or preview
  recomputations; a live run-ID change causes exactly one.
- A synthetic million-entry iterator stays within the visit/retention/path
  budgets without allocating or sorting the full input.
- Cancellation during chunked traversal releases the worker slot, target
  round-trips remain isolated, and stale generations cannot publish.
- File-picker, Tab/fuzzy completion, TUI focused tests, Clippy, formatting, and
  CRAP gates pass.

## Done criteria

Unrelated progress cannot defeat memoization, and every file-completion walk
has a tested work, memory, and cancellation bound.

## Implementation notes

- Generic scan/activity mutation no longer invalidates completion previews.
  Scan, activity, and tool run IDs compare their effective old/new values at
  the mutation boundary, so an unchanged ID preserves the memo.
- File completion discovery now enforces 100,000 entry visits, 5,000 retained
  paths, depth 32, and 8 MiB of observed relative-path bytes before allocation
  can grow with the full tree. A bounded max-heap retains a stable sorted page.
- Discovery publishes explicit partial-index reasons for every exhausted
  budget and for unreadable directories, entries, or file types. The picker
  tells the operator to paste an exact path when a file is missing.
- Hydration batches carry cancellation tokens. Target changes and same-target
  invalidation cancel stale walks; workers observe cancellation between
  128-entry directory chunks, and generation checks still reject stale output.

## Verification evidence

- `cargo check -p kuzushi-tui --tests` passed after the semantic invalidation,
  metadata, and cancellation wiring.
- `cargo test -p kuzushi-tui file_picker -- --nocapture` passed 14 focused
  tests; `cargo test -p kuzushi-tui view_hydration -- --nocapture` passed 27.
  These include the 5,000-value memo, same-ID progress mutations, identical
  cache writes, million-item lazy input, bounded traversal cancellation, stale
  generation rejection, and worker-slot release.
- The final cohesion extraction into `file_picker/discovery.rs` and
  `view_hydration/runtime/worker.rs` passes the focused CRAP-risk proxy for all
  owned files and `git diff --check`. The post-extraction Cargo rerun was
  attempted but the shared tree was transiently uncompilable in concurrent
  Plan 020/034 files (`materialize_bound_tree` modules and `trace_cost.rs`),
  unrelated to this plan; root review accepted the focused proof.
