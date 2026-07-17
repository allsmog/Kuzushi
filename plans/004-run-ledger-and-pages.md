# Plan 004: Make run terminalization atomic and run-history pages bounded

> Executor: edit only the run-artifact ledger/index and directly consuming TUI
> hydration code. Preserve existing run formats and dirty-tree changes.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: correctness/perf
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

Stale-run recovery bypasses the terminal lock/digest invariant, so concurrent
readers can append duplicate interruption events and leave a terminal summary
that normal retry rejects. Separately, the `page` API reads and sorts the whole
history before slicing, so the latest-100 contract is not bounded.

## Current state

- `run_summary_store.rs::repair_stale_running_summary` calls a direct
  `persist_interrupted_repair` from read paths.
- `run_ledger.rs` owns the terminal lock; `running.rs` defines terminal result
  digests; `tool_run_record.rs` contains normal idempotent terminalization.
- `list_run_summary_entries_page` currently calls the complete list first.
- TUI hydration requests the latest 100 in
  `crates/kuzushi-tui/src/app/view_hydration/reader.rs`.
- Preserve `.kuzushi/v3/runs/<runId>` schema and legacy visibility.

## Steps

1. Put stale recovery under the existing terminal lock, reload raw summary
   inside the lock without recursive repair, and recheck both `running` state
   and dead owner before mutation.
2. Produce a deterministic interrupted terminal intent/digest and reuse the
   canonical result/event/trace persistence helpers. Repeated same-content
   recovery must repair missing derived artifacts but append no duplicates.
3. Add concurrency tests with multiple readers plus tests for digest presence,
   same-content retry, and recovery after a missing result/event/trace.
4. Add an atomically maintained run-history index containing run id, canonical
   sort key, and issue state. Terminal/start writes update it under a scoped
   lock. Page reads use only the required bounded prefix/window.
5. On absent/invalid index, rebuild once from legacy directories, publish it
   atomically, and keep the full-scan API for export/repair. Add migration,
   malformed-entry, ordering, and concurrent-terminalization tests.

## Verification

```text
cargo test -p kuzushi-core run_artifacts --offline
cargo test -p kuzushi-tui view_hydration --offline
pnpm quality:crap-risk
```

## Done criteria

- Stale repair has a terminal digest and is lock/idempotence safe.
- Missing canonical artifacts can be repaired after terminal summary creation.
- A latest-100 page does not deserialize/sort every historical run when a valid
  index exists.
- Legacy workspaces retain deterministic complete visibility.

## STOP conditions

Stop if the design changes published run JSON/schema incompatibly, takes a
global workspace lock, or makes ordinary read APIs recursively acquire the
same terminal lock.
