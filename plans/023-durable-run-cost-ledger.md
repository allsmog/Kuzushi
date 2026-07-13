# Plan 023: Preserve run cost caps across sequential and restarted workers

> Executor: spending is a fail-closed invariant. Never reset, estimate down, or
> silently forgive a reservation whose provider outcome is unknown.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Category**: cost governance/correctness
- **Depends on**: Plan 015
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

The registry retains only weak ledger references and removes an entry when the
last invocation lease drops. A later worker with the same target/run ID starts
from zero, so `maxCostUsdPerRun` is enforced only across overlapping leases, not
sequential tool invocations. A process restart also forgets real spend.

## Steps

1. Add a regression proving two non-overlapping invocations under the same
   target/run share committed spend and cannot together exceed the run cap.
   Cover `CapabilityBroker` and the live `WorkerHostSession` path.
2. Make the target-qualified run ledger durable or explicitly owned by the
   canonical run lifecycle. A durable private run artifact plus OS file lock is
   preferred: atomically reserve before a provider call and commit actual cost
   after it returns. Concurrent processes must observe one serializable total.
3. On crash/restart, treat an unresolved reservation conservatively (at least
   its reserved amount) until an explicit reconciled terminal record exists;
   never assume the provider spent zero. Validate schema, file identity, finite
   values, target/run binding, and bounded size.
4. Clean transient registry state only after canonical run terminalization;
   preserve the durable receipt needed by run summary/audit and safely rebuild
   in-memory state. Keep per-invocation cost reporting separate from run total.
5. Reconcile the final ledger total with canonical `run.json.costUsd` and audit
   records without double counting child/tool costs.

## Verification

- Sequential, concurrent, cross-process/reopen, and same-run/different-target
  tests cannot overspend.
- Failed calls roll back; provider overruns are charged and denied; simulated
  crash after reserve fails closed on restart.
- Terminal cleanup is bounded and never erases the canonical spend receipt.
- Worker/KWP, run-artifact, benchmark-spend, Clippy, model-safety, architecture,
  and CRAP gates pass.

## Done criteria

`maxCostUsdPerRun` means the complete target-qualified run, independent of
invocation overlap or process lifetime.
