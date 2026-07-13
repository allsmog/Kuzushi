# Plan 006: Bound and reuse worker/MCP resources behind cohesive modules

> Executor: perform an incremental extraction, not a whole-file rewrite. Keep
> public KWP types, RPC JSON, audit serialization, and cancellation order exact.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: Plan 002
- **Category**: perf/tech-debt
- **Planned at**: commit `775a4134f2cb`, 2026-07-12

## Why this matters

The KWP host has unbounded stderr line drains, constructs a new pinned HTTP
client for every fetch, and mixes trust, audit, MCP, network, RPC, and process
lifecycle in one ~6,500-line production file. File hashing also buffers and
copies entire binaries. These cause avoidable latency/RSS and make policy
changes difficult to review.

## Current state

- `crates/kuzushi-core/src/worker_protocol.rs`: unjoined `BufRead::lines()`
  drains near MCP/worker spawn; `net.fetch` constructs a blocking client on
  each request; tests start after thousands of mixed production lines.
- `crates/kuzushi-core/src/bounded_subprocess/` contains bounded-drain patterns.
- `crates/kuzushi-mcp-common/src/cache/sha256.rs` reads a whole file and the
  custom hash implementation copies it again.
- Preserve cache digest bytes and all public worker contracts.

## Steps

1. Add a supervised stderr forwarder with per-line and total preview caps that
   continues draining after truncation. Retain/join handles and surface read or
   truncation diagnostics without deadlocking child exit.
2. Add a session-local pinned HTTP client pool keyed by validated host, pinned
   socket, timeout, and transport policy. Equivalent requests reuse a client;
   changed pins/timeouts cannot.
3. Stream `sha256_file_hex` through a vetted incremental SHA-256 implementation
   with bounded buffering. Preserve exact known vectors/cache keys.
4. Extract the touched cohesive internals from `worker_protocol.rs` into
   `worker_protocol/{stderr,net,mcp,host_session}.rs` (or equivalently narrow
   names) behind private imports/compatibility re-exports. Do not move unrelated
   domains in this pass merely to reduce line count.
5. Add tests for newline-free/noisy stderr, drain-after-truncation, join errors,
   client reuse and key isolation, and streamed multi-chunk hashes.

## Verification

```text
cargo test -p kuzushi-core worker_protocol --offline
cargo test -p kuzushi-mcp-common cache --offline
pnpm quality:architecture
pnpm quality:crap-risk
```

## Done criteria

- Child stderr allocation/forwarding is bounded while pipes are always drained.
- Equivalent fetches reuse clients without weakening DNS pinning.
- Hashing peak memory is independent of file size and digests are identical.
- Touched worker responsibilities live in focused modules; public behavior is
  unchanged.

## STOP conditions

Stop if client reuse weakens rebinding protection, stderr truncation can block a
child, digest output changes, or extraction requires a broad public API change.
