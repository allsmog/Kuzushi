# V3 Persistence And Index Architecture

Kuzushi v3 separates durable truth from read convenience.

```text
source snapshot + CAS objects     canonical for code-derived facts
append-only event log             canonical for human/proof/rekey/audit decisions
SQLite projection                 disposable read model and search index
single writer actor               only append/projection mutation boundary
TUI, CLI, reports                 readers by projection watermark
```

SQLite may lag the event log, but it must never be ahead of the event log.
`meta.applied_seq` is committed in the same SQLite transaction as the rows and
FTS changes it covers.

## Filesystem

Target-owned state lives under:

```text
<target>/.kuzushi/v3/
  index.sqlite3
  objects/blake3/<hh>/<hh>/<hash>
  log/events-000000.jsonl
  log/checkpoints/checkpoint-000000000123.json
  runs/<runId>/
    run.json
    items.jsonl
    events.jsonl
    input.json
    result.json
    failures.json
    report.md
    artifacts.json
    scan-input.json, triage.jsonl, verify.jsonl, patch.jsonl  # sast:scan only
  latest
  workflow/phase-attempts.v2.jsonl
```

The run directory remains an operator-facing replay/export bundle. It is not a
second mutable state store. Snapshot-style files such as `context.json`,
`attack-surface.json`, `findings.json`, and `proof.json` are no longer
synthesized as fixed run leaves. A producer may declare those files explicitly
in `artifacts.json`, but otherwise those payloads live in `result.json`, CAS
objects, events, or rebuilt SQLite projections.

The run id created by the caller is the canonical identity for an umbrella
scan. Per-engine ids are retained as child provenance, and scan policy/export
queries read the parent/child union. Run lifecycle rows are written as
`running` before fallible finding persistence and are terminalized as
`completed` or `failed`; import and scanner writers use the same guarded
start/operation/finish shape.

## Source Of Truth

| Record | Canonical source | SQLite role |
| --- | --- | --- |
| File bytes | CAS blob in `objects/` | indexed file row |
| Tree/snapshot | CAS tree and snapshot object | lookup/cache |
| Scanner observation | event log payload plus CAS/source refs | finding projection |
| Stable finding state | folded observations, rekeys, decisions | current read model |
| Triage/suppression | append-only event | projected review state |
| Verification/proof | append-only event | projected proof state |
| Patch attempt | append-only event plus optional CAS diff | projected audit row |
| Reports | derived export | optional cached artifact |
| Per-run task/call/terminal lifecycle | hash-linked `runs/<runId>/items.jsonl` | pure in-memory/live/replay projection |
| FTS rows | projection data | disposable search index |

The target-wide event log remains canonical for findings and target state. A
terminal run item is bridged to it idempotently, but run replay reduces the
per-run typed stream and never reconstructs from the target log.

Direct mutation of projected findings for human decisions is forbidden.
`record_auto_triage` appends a v3 decision event and lets the projection update
the finding JSON in the same transaction as `applied_seq`.

## Writer State Machine

The storage writer lifecycle is explicit:

```text
Recovering
  verify event chain
  open projection
  reject if applied_seq > log head
    |
    v
Replaying
  apply log events after applied_seq
  advance projection watermark per event
    |
    v
Live
  append event
  project event
  commit rows + applied_seq together
    |             |
    |             +-- Checkpoint/Compact -> Compacting -> Live
    +-- RebuildProjection -> Rebuilding -> Replaying/Live
    +-- Shutdown -> Draining -> Stopped
```

Invalid transitions are hard errors. Projection watermarks may only move
forward and may never pass the event-log head.

## Writer Lanes

The live actor has three lanes:

| Lane | Contents | Policy |
| --- | --- | --- |
| Control | checkpoint, rebuild, compact, barrier, shutdown | drained first |
| Decision | triage, suppression, verification, patch, audit, rekey | bounded, never silently dropped |
| Watcher | file/index/observation batches | bounded and coalescible when re-derivable |

Scheduling drains all ready control commands, then up to the decision budget,
then one watcher command. This keeps watcher/index churn from starving human
decisions.

## Read Protocol

Read APIs return the projection watermark with their rows. Callers that need
read-your-writes pass `ReadOptions::wait_for_min_seq(committed_seq, timeout)`.

Policies:

- `AllowStale`: serve current projection.
- `RejectStale`: fail if `applied_seq < min_seq`.
- `Wait`: poll until the projection reaches `min_seq` or return an explicit
  timeout.

TUI decisions must carry the view watermark they were made from. The writer
checks events after that watermark. A safe rekey forwards the decision to the
new stable finding; conflicting intervening changes are rejected so the
operator reloads before deciding.

## Implementation Map

- `crates/kuzushi-core/src/content_store/` - CAS objects and snapshots.
- `crates/kuzushi-core/src/event_log/` - hash-chained JSONL event log.
- `crates/kuzushi-core/src/storage_v3/` - projection schema, replay, FTS, and
  read watermark policy.
- `crates/kuzushi-core/src/storage_v3/writer_actor.rs` and
  `writer_actor/` - lane scheduler, lifecycle, stale-decision handling, and
  command execution.
- `crates/kuzushi-core/src/run_artifacts/` - run exports and CAS artifact
  recording.

## Deletion Policy

There is no backward-compatibility layer for old mutable state as a product
goal. Keep compatibility aliases only at external file/schema parse boundaries
while producers are being updated. Do not add new direct SQLite write paths,
parallel run-state JSON stores, or TUI-owned findings state.
