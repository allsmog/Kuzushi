# Plan 012: Make run history scalable and stale-process identity exact

> Executor: canonical per-run JSON/result/event/trace files remain the source of
> truth. The history index is rebuildable and must never wedge canonical writes.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: correctness/performance/persistence
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Every summary update rewrites the complete sorted history index, deep pages
parse all preceding rows, and entry 100,001 leaves canonical data written but
the derived index permanently dirty. Stale-run repair also treats PID liveness
as process identity, so PID reuse or zombies can keep dead runs `running`.

## Steps

1. Replace full-index rewrites with a safe append/upsert journal plus bounded
   compaction, or another row-oriented rebuildable index with O(log R) writes
   and indexed pages. Use existing symlink-safe/atomic persistence primitives.
2. Bound journal/snapshot reads and compaction work. Retain a recent indexed
   window when necessary, record truncation/total-count metadata, and keep full
   directory scan/export able to reach older runs.
3. Index failure must leave an explicit dirty/degraded marker but must not make
   a valid canonical run summary unusable. A later read/rebuild repairs it.
4. Persist process birth identity with PID: Linux start time plus boot ID and
   platform equivalents where available. Treat zombies as dead.
5. Make legacy PID-only records conservatively recoverable without changing
   existing JSON fields or terminal digest semantics.

## Verification

- N+1 boundary and large-history tests keep new writes and recent pages working.
- Repeated start/terminal upserts do not duplicate rows and avoid O(R) rewrites.
- Crash, dirty-marker, corruption, legacy migration, full export, and concurrent
  reader/writer tests remain green.
- Current PID plus mismatched birth token and zombie fixtures recover as stale.
- Run core run-artifact tests, TUI history tests, Clippy, and CRAP gates.

## Done criteria

History maintenance is bounded and rebuildable at any run count, and only the
original live process can keep a run in `running` state.
