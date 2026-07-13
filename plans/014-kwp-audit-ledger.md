# Plan 014: Make KWP audit appends constant-time and run-scoped

> Executor: preserve the hash-chain wire/file format and tamper detection. Do
> not weaken replay verification or fsync durability.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: performance/persistence
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Each broker decision rereads, parses, and rehashes the entire audit log before
append, making N calls quadratic. One process-global mutex also serializes
unrelated targets/runs.

## Steps

1. Validate the existing chain once when opening a run-scoped audit writer and
   retain only the last sequence/hash plus safe append handle in memory.
2. Append, flush/fsync, and advance the tail in O(1). Never advance memory state
   before durable append succeeds.
3. Key locks/writers by target-qualified run identity and clean them up at
   terminalization. Keep a bounded registry for abandoned sessions.
4. Preserve full-chain verification for replay/startup and repair only through
   an explicit verified path; detect external mutation between appends.

## Verification

- Tamper, truncation, interrupted append, concurrent same-run append, and
  unrelated-run concurrency tests.
- Instrument bytes/records read for 1,000 appends and prove linear total work,
  with constant work after writer initialization.
- Run KWP tests, artifact contract, Clippy, and CRAP gates.

## Done criteria

Audit durability and tamper evidence remain intact without whole-log work per
broker decision or global cross-run serialization.
