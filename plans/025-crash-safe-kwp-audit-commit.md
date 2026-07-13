# Plan 025: Make KWP audit commits crash-recoverable and process-serialized

> Executor: preserve the existing record/hash-chain and anchor wire formats
> where possible. Recovery must be explicit, verified, and itself auditable.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED-HIGH
- **Category**: audit persistence/reliability
- **Depends on**: Plans 014 and 024
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

An append fsyncs the JSONL record and then atomically rewrites the anchor. A
crash or anchor-write failure between those steps leaves a valid extra record
with an old anchor; startup rejects the log permanently. The in-memory registry
also serializes only one process, so two Kuzushi processes can race on the same
target/run chain.

## Steps

1. Add a target/run-qualified OS lock covering initial verification, append,
   durable record commit, anchor advancement, and recovery. Keep unrelated runs
   concurrent and preserve the in-process fast path.
2. Define a recoverable commit protocol with a durable pending-commit journal
   that binds the anchored prefix and exact next record/hash before the log is
   appended. Recover only when the journal, anchored prefix, and observed tail
   match exactly; a merely valid unjournaled hash-chain extension is tampering.
   Repair/trim only under the lock with fsyncs and a recovery audit marker; all
   other divergence remains fail-closed.
3. Never advance memory state until both durable stages succeed. If anchor
   advancement fails, poison/close the writer and make a subsequent open take
   the verified recovery path rather than mislabeling its own append as external
   mutation.
4. Combine recovery with Plan 024's byte/record limits and exact file-identity
   checks on Unix and Windows.

## Verification

- Fault injection at every write/flush/fsync/rename boundary either returns the
  prior anchored log or recovers the one committed next record; it never bricks
  valid history or accepts arbitrary divergence.
- Partial tail, stale anchor, advanced anchor, truncation, rewritten same-size
  content, cross-process append, and unrelated-run concurrency tests.
- 1,000 normal appends retain constant post-open work and valid replay.
- Worker/KWP, platform cfg, Clippy, artifact-contract, and CRAP gates pass.

## Completion evidence

- The worker-protocol suite passes 136/136. Its 20 focused audit-writer tests
  cover subprocess serialization, cached cross-process refresh, exact-capacity
  recovery at each durable boundary, partial recovery-marker writes, fallback
  finalization after panic/replacement failure/process death, tamper rejection,
  deadline-aware lock contention, and the last-slot two-process race.
- Unknown successful provider spend remains conservatively charged across a
  durable-ledger reopen; exact worker cost receipts still drive invocation and
  run totals without double counting.
- Native `x86_64-pc-windows-msvc` cfg compilation passes for the exact lock and
  audit identity modules using stable Win32 handle identity APIs. The full
  cross-target crate check reaches `ring` but cannot build its C code on this
  macOS host because Windows SDK headers are unavailable.
- `cargo check -p kuzushi-core --lib` and plan-scoped Clippy with warnings
  denied pass. Model-safety, artifact, environment-discipline, dispatch, and
  workspace-state contracts pass. Whole-tree strict Clippy, architecture, and
  CRAP remain blocked only by concurrently edited files outside Plan 025; no
  Plan 025 file appears in the CRAP failure report.

## Done criteria

Power loss or process overlap cannot corrupt a legitimate KWP audit chain, and
tamper detection remains fail closed outside the documented commit states.
