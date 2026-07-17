# Plan 013: Memoize TUI completion previews and bound recent-run hydration

> Executor: preserve completion ordering, keyboard behavior, target generation
guards, and the rule that rendering performs no filesystem or database I/O.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Category**: performance/TUI
- **Depends on**: Plan 012 for bounded recent-run paging
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Each frame with nonempty input clones cached vectors, deduplicates thousands of
values, fuzzy-ranks, and formats matches. Run hydration also scans/sorts every
run directory. The filesystem moved off the render path, but the CPU/allocation
cost remains frame-bound.

## Steps

1. Add a completion-preview cache keyed by editor revision, cursor/mode,
   target/cache generation, and command-provider generation.
2. Recompute candidates only when that key changes; render borrowed/shared
   preview lines without cloning 5,000-entry source vectors.
3. Replace full run-directory enumeration with the bounded recent-history API
   from Plan 012, while merging live run IDs without duplicates.
4. Invalidate explicitly on target, findings, file, run, command, and input
   changes. Stale hydration generations must never overwrite a current cache.

## Verification

- Instrument providers and prove repeated renders perform zero recomputations,
  clones of source vectors, or I/O until an input/generation change.
- Preserve Tab cycling, fuzzy ordering, file picker pending refresh, target
  switching, and live-run merging tests.
- Add a 5,000-file/large-history latency-allocation regression benchmark.

## Done criteria

Steady-state rendering consumes a precomputed preview, with bounded work on
input/cache changes only.
