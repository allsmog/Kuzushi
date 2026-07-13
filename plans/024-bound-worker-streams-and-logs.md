# Plan 024: Bound fuzz, directory, audit, and bus I/O end to end

> Executor: preserve watchdog cancellation and protocol shapes. A limit must be
> reported as a quota/deadline result, never as a successful truncated scan.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: MED-HIGH
- **Category**: availability/resource management
- **Depends on**: Plans 009 and 014
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

Fuzz executors write stdout/stderr to unbounded temp files; stderr is read fully
even after timeout and stdout is read fully on completion. A child can exhaust
disk and then memory before the watchdog result is returned. Filesystem listing
collects an unbounded directory before RPC encoding rejects an oversized
response. Audit and bus replay use unbounded `read_to_string`, and their append
paths have no total log cap.

## Steps

1. Replace fuzz temp-file capture with fully drained bounded pipes or another
   streaming collector. Retain only a capped stdout result and escaped stderr
   preview, signal overflow, and ensure timeout/cancellation kills and reaps the
   complete child process group without loading discarded bytes.
2. Bound directory entry enumeration and response construction before
   allocation/serialization. Reject or explicitly page at the cap; preserve
   deterministic ordering and account the operation against the grant.
3. Add shared bounded JSONL streaming for audit and bus logs: maximum file
   bytes, records, line bytes, decoded payload bytes, and append growth. Inspect
   metadata before allocation and read incrementally with no-follow identity
   checks. A full log must refuse further privileged work honestly.
4. Bound bus-event payload serialization and make same-run append concurrency
   produce complete non-interleaved lines. Keep unrelated runs independent.
5. Audit other child/file reads in the touched broker path and route them
   through the same constants/helpers instead of leaving an unbounded fallback.

## Verification

- Infinite/huge fuzz stdout and stderr fixtures stay within memory/disk caps,
  terminate by quota/deadline, and leave no child PID.
- Huge directories and oversized audit/bus files fail before large allocation.
- Boundary-size data succeeds; limit+1 fails with stable resource labels.
- Concurrent bus/audit lines remain parseable and target/run isolated.
- Worker/KWP tests, resource stress tests, Clippy, architecture, model-safety,
  and CRAP gates pass.

## Completion evidence

- Worker-protocol tests pass 118/118, including infinite fuzz stdout/stderr,
  deadline reaping, concurrent same-run bus appends, and target/run isolation.
- Exact byte/record/line/decoded-payload boundaries succeed; limit-plus-one
  fixtures return stable quota labels. Oversized audit/bus files are rejected
  from metadata before replay allocation.
- Plan-scoped Clippy is clean with warnings denied, architecture and model
  safety pass, and the CRAP proxy reports no Plan 024 files or functions.
  A transient strict-Clippy dead-code lint remains only in the concurrently
  edited Plan 029 `process_identity.rs` surface.

## Done criteria

Every worker-owned stream, listing, and replay path has a tested finite budget
that is enforced before disk or memory can grow without bound.
