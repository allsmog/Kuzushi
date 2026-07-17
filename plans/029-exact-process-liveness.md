# Plan 029: Distinguish missing process identity from corruption and test liveness exactly

> Executor: retain the intentional legacy fallback only for a genuinely absent
> sidecar. Existing unsafe or malformed evidence must never become proof that a
> process still owns a run.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Category**: run lifecycle/cross-platform correctness
- **Depends on**: Plan 012
- **Planned at**: commit `775a4134f2cb`, Cycle 6

## Why this matters

Process-identity loading currently maps missing, unreadable, oversized,
symlinked, and malformed sidecars to the same `None`, then treats the original
PID as alive. That lets corrupted evidence disable PID-reuse detection. On
Windows, `GetExitCodeProcess == STILL_ACTIVE` also misclassifies a terminated
process whose actual exit code is 259.

## Steps

1. Return a typed identity-read outcome that distinguishes genuine `NotFound`
   legacy absence from valid identity, invalid schema/JSON, unsafe path type,
   oversize, unreadable bytes, and binding mismatch.
2. Permit the legacy PID-only fallback only for genuine absence. Treat every
   existing invalid/unsafe sidecar as non-owner evidence so history repair
   marks the orphaned run interrupted, while retaining an actionable issue in
   diagnostics where the public shape allows it.
3. On Windows, determine signaled/dead state with a zero-time handle wait using
   the required synchronization right. Query the creation token only after the
   wait proves the process is still live; map failed waits conservatively to
   unknown.
4. Keep Linux zombie/start-tick, macOS birth-time, and legacy-platform behavior
   unchanged and test the shared decision table as pure logic.

## Verification

- A live current PID plus malformed JSON, unknown fields, invalid UTF-8,
  limit+1 bytes, a directory, or a symlink sidecar is never accepted as the
  original owner; a truly missing sidecar retains documented legacy behavior.
- PID birth-token mismatch remains stale even when the PID is live.
- A Windows-only child exiting with code 259 observes `Dead`; a running child
  observes `Alive` with its creation identity.
- Run-history/process-identity tests, Windows cfg/cross-checks, Clippy,
  formatting, and CRAP pass.

## Done criteria

Only absent legacy evidence receives a fallback, and operating-system process
state cannot confuse an exit-code value with liveness.

## Execution record

- Native process-identity, liveness, bounded-file, and run-artifact suites pass.
- The installed Windows target cannot complete the full dependency graph on
  this macOS host because `ring` reaches the C compiler without Windows SDK
  headers (`assert.h` is missing), before `kuzushi-core` is checked.
- An isolated metadata-only Windows-target compile of the exact
  `OpenProcess`/`WaitForSingleObject`/`GetProcessTimes` and
  `CreateFileW`/reparse-point APIs passes against the resolved `windows-sys`
  dependency. Windows-only tests cover wait-result decisions, exit code 259,
  live-child creation identity, and reparse rejection for a real Windows run.
