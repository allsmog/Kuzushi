# 0002 — Reproducible scan batches

- Status: Accepted
- Date: 2026-08-27
- Owner: `@allsmog`

## Decision

Repeated scans use a dedicated `kind: "scan-batch"` campaign plan. Missing
`kind` continues to mean the existing generic campaign. Batch compilation does
not call generic coverage or `fillGaps` logic.

The plan records `batchId`, `trialsPlanned`, one logical trial per job, gate
policy, and a canonical `BatchEquivalenceKey`. The key records and hashes the
prepared input, complete Git/worktree identity, config, loaded descriptor and
module set, runtime/model/provider binding, immutable threat-model ref, prompt
and house-rule hashes, scope/decomposition, engine/cache identity, and Kuzushi
version. Each child recomputes the full key at the `sast:scan` consumption
boundary and persists `batch-equivalence.json` with the consumed components.
Drift blocks that child and every unstarted trial; v1 never silently splits a
comparability group.

A trial is a logical sample. Dispatcher attempts are retries of that sample.
Only one successful result per trial contributes to occurrence. Failed,
parked, and blocked trials stay visible and outside the completed denominator.

`scan --trials N --workers W` executes synchronously through detached campaign
children. The immutable plan records requested and effective workers plus the
complete resource-claim receipt; the dispatcher refuses a contradictory or
different ceiling. Workers cannot exceed the number of logical trials or the
dispatcher hard cap of eight. `--attempts` and `--samples` remain deprecated
aliases for trials, which are capped at 100. Dispatcher attempts remain a
separate retry budget.

Children never run a final CI gate. The controller emits one safe-folded SARIF
and applies one gate. Any completed trial observing an unsuppressed finding at
or above the threshold trips the gate. Output precedes exit: code 3 is a
security gate result, code 1 is incomplete operational execution, and code 0
is a complete clean result. The durable gate binds the complete logical-trial
state, completed run ids, safe-fold blocking set, and digest of the atomically
published final SARIF; a stale receipt is refused or recomputed by the
controller.

Stage 5 reuses detached `kuzushi campaign run` processes for the TUI. The
headless `scan --trials` controller remains synchronous when it owns
`--fail-on` or `--sarif`; no CLI detach surface may imply that an acceptance
receipt is a final security result.

Parallel eligibility comes from one shared scan-task resource-claim registry
consumed by CLI and TUI, not mode-local scanner-name branching. Automatic,
missing, or unresolved metadata means `Unknown`; Unknown or any
workspace-exclusive resource clamps concurrency to one and names the
responsible task/resource. CodeQL database and cpg-rs graph users are explicit
workspace-exclusive claims.

## Consequences

Occurrence reports are derived from plans, queue state, run receipts, and
findings. They are not persisted as a second truth. Quorum gates and automatic
mixed-group splitting are deferred.

Child processes share findings storage through its cross-process writer lock,
fsynced event log, WAL projection, and replay-on-open recovery. The campaign
queue remains controller-owned (children never write it), so queue cost tests
exercise retry accumulation in the controller while the process fault test
targets concurrent findings/run/identity writes plus reader refresh.
