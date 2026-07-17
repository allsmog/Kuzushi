# Plan 030: Keep run-history pages bounded and fail closed when truncation prevents authenticity

> Executor: canonical per-run artifacts remain the source of truth. The SQLite
> file is disposable derived state and must never silently hide, reorder, or
> permanently wedge that truth.

## Status

- **Status**: DONE
- **Source readiness**: COMPLETE; focused and full-workspace verification passed
- **Priority**: P1
- **Effort**: L
- **Risk**: MED-HIGH
- **Category**: persistence/scalability/integrity
- **Depends on**: Plan 012
- **Planned at**: commit `775a4134f2cb`, Cycle 6

## Why this matters

A legitimate corpus large enough to exceed the 512 MiB SQLite ceiling rebuilds
into the same failure forever. Logical row deletion or timestamp tampering can
also pass schema plus directory-mtime validation and hide/reorder canonical
runs. A retained prefix cannot prove that an arbitrary evicted `run.json` was
not rewritten above it without either reading every evicted file or relying on
a trusted mutation journal. Deep pages use `OFFSET`, so work grows linearly
with skipped history, and an invalid dirty-marker node triggers a full rebuild
on every read because its failed removal is ignored.

## Steps

1. Define a bounded newest-history retention contract for the derived index.
   Rebuild/upsert only the configured row/byte window and persist validated
   total-count, retained-count, oldest-cursor, truncation, and canonical
   generation metadata. When retention is truncated, bounded page APIs must
   fail closed with an actionable route to the explicit full canonical scan;
   they cannot honestly certify the retained prefix against arbitrary evicted
   file edits. Full export/scan APIs must continue to reach canonical older
   artifacts explicitly.
2. Bind index metadata to canonical directory state strongly enough that row
   deletion and ordering-key mutation are detected for an untruncated index.
   Validate stored count against table count and verify returned rows/order
   against bounded canonical metadata or a writer-owned generation/digest
   contract; rebuild on mismatch. Treat truncation as an explicit proof gap,
   not as permission to certify only the visible prefix.
3. Add keyset pagination over the canonical ordering tuple. Keep offset
   compatibility only behind an explicit finite cap or sparse checkpoints so a
   deep request cannot linearly discard unbounded rows.
4. Under the history lock, safely remove/quarantine an invalid dirty-marker
   node or enter a visible bounded degraded mode. Never ignore a failed clear
   and repeat a full rebuild indefinitely.
5. Keep SQLite no-follow, defensive/trusted-schema, page/cache/mmap, and
   no-sidecar constraints intact; validate every new header field and arithmetic
   conversion before use.

## Verification

- With injectable low row/byte limits, a canonical corpus beyond the index cap
  makes offset and cursor pages fail closed without silently running an
  unbounded scan. The actionable error directs callers to the documented full
  canonical path, which still reaches every run and observes evicted edits.
- Deleting an indexed row or changing its timestamp causes a rebuild and
  restores canonical IDs/order.
- Instrumented keyset pages perform bounded work independent of a 100,000-row
  logical depth; invalid/excessive cursors fail closed.
- A directory/symlink/other invalid dirty marker causes at most one recovery or
  a stable degraded state, never one full scan per page.
- Run-artifact tests, Clippy, formatting, package/schema/docs, and CRAP gates
  pass.

## Done criteria

The disposable index stays finite and fast. Every returned page is an honest
projection of canonical run artifacts; when a bounded proof is impossible
because retention evicted canonical rows, page APIs fail closed instead.

## Implementation notes

- Replaced the unbounded JSONL projection with a rebuildable SQLite v3 index
  that retains a validated newest-first row/byte window while streaming the
  full canonical corpus for total and digest metadata.
- Added generation-bound keyset cursors over the complete ordering tuple,
  capped legacy offsets, strict row/schema/metadata validation, and canonical
  materialization checks before a page is returned.
- Added serialized incremental updates, stable directory snapshots, fresh
  rebuild generations, and deterministic quarantine for invalid dirty-marker
  nodes. Rebuilds preserve a readable persisted retention policy.
- Added focused regression coverage for retention bounds, evicted updates,
  tied timestamps, stale cursors, corrupt indexes, canonical timestamp drift,
  off-page canonical reordering under a one-row page, hidden ordering-key
  mutation, directory races, and stable quarantine failure. Untruncated page
  reads validate the complete row/byte-capped retained window as their ordering
  witness, then recheck the writer-owned dirty/generation contract before
  returning. Truncated offset and cursor reads fail closed because no bounded
  witness can exclude an arbitrary evicted-file rewrite; callers must choose
  the explicit full canonical scan rather than receiving a silent unbounded
  fallback. Dirty/rebuild transitions still protect canonical writer updates.
- Source formatting and the full changed-code CRAP-risk gate pass. The focused
  run-history filter passes 9/9, the retention filter passes 5/5, and the exact
  evicted-run offset/cursor fail-closed regressions pass 2/2.
- The final offline workspace run passed, including 3,185 core tests, 1,849 TUI
  tests, all 26 snapshots, strict all-target Clippy, and the shared policy
  gates.
