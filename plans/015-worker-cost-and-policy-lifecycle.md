# Plan 015: Give worker cost and policy one lifecycle-owned implementation

> Executor: characterize behavior before deleting or redirecting abstractions.
> Preserve grants, budgets, audit events, KWP errors, and no-silent-fallback.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: MED-HIGH
- **Category**: architecture/correctness/resource management
- **Depends on**: Plan 014
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Worker cost uses a process-global map keyed only by run ID, never evicts, and
checks then adds separately. The live `WorkerHostSession` also duplicates the
authorization/meter/audit behavior of a dormant `CapabilityBroker`, leaving two
policy implementations inside an 8,000-line module.

## Steps

1. Add characterization tests comparing every privileged live method with the
   intended broker grant, meter, audit, error, and path/network rules.
2. Introduce a target-qualified, lifecycle-owned cost ledger with atomic
   reservation/commit/rollback so concurrent requests cannot overspend.
3. Attach ledger/audit lifetime to the worker/run session and remove state at
   terminalization; bound cleanup for abnormal exits.
4. Extract shared pure authorization/metering primitives used by the live
   session. Either route `CapabilityBroker` through them or remove the dormant
   abstraction after proving no public/production consumer exists.
5. Split only stable cohesive seams from `worker_protocol.rs`; preserve public
   exports and protocol compatibility shims.

## Verification

- Same run ID in two targets has isolated budgets.
- Concurrent reservations cannot exceed the cap; failures roll back; terminal
  sessions release registry state.
- Characterization matrix covers fs, net, runtime, MCP, fuzz, finding and audit
  methods before/after extraction.
- Full worker/KWP tests, architecture/model-safety, Clippy, and CRAP gates pass.

## Done criteria

One tested policy core serves the live path, and all mutable budget/audit state
has an explicit target-qualified lifecycle.
