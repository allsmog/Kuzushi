# 0001 — Threat-model lineages, revisions, and activation

- Status: Accepted
- Date: 2026-08-27
- Owner: `@allsmog`

## Decision

A threat model has an immutable lineage id (`tm_<32 lowercase hex>`) and each
content revision has an immutable revision id (`tmr_<32 lowercase hex>`).
`ThreatModelRef` contains both ids and a `sha256:<64 lowercase hex>` digest.
Scope and methodology are searchable metadata, never identity.

`.kuzushi/threat-models/manifest.json` is authoritative. Schema v1 contains a
monotonic generation, the active ref, a recoverable last-activation checkpoint,
and model lineages with head and revision metadata. Canonical full-document
JSON is stored once under `objects/sha256-<digest>.json`. Activation events are
append-only in `activations.jsonl`; `.kuzushi/threat-model.json` is a derived
compatibility mirror.

All mutation holds one exclusive store lock. It validates and canonicalizes the
document and durably writes the object. An activation then persists a
generation-bound mirror-commit intent and withdraws the reconciled old mirror
before committing the next manifest generation. It idempotently appends the
manifest's activation checkpoint, materializes the new mirror, and durably
clears the intent. Writable open repairs a missing mirror from the manifest for
either side of an interrupted commit; an existing divergent mirror is never
classified as crash residue. Orphan objects are retained. A missing or corrupt
active object is an integrity error.

A divergent legacy mirror is never overwritten implicitly. The operator must
adopt it as a revision, discard it with an explicit forced action that records
the discarded SHA, or inspect a read-only diff.

The first writable open without a manifest imports a valid legacy mirror as a
single lineage and active revision. Read-only open never migrates. Historical
SQLite version rows stay readable as legacy history; restoring one creates a
new revision instead of inventing lineage metadata for old rows.

Build, refine, verify, restore, and adopt create immutable revisions. Supplying
`modelId` appends to that lineage. A second lineage in the same
scope/methodology requires `newModel=true`. Restore creates a new head sourced
from the historical revision and activates it. Activation alone changes only
the pointer and audit event.

`ScopeRef` binds `scopeId`, normalized `relPath`, `projectModelSha256`, and
`targetRevision`. `ThreatModelBuildRoots` separates workspace persistence from
the canonical descendant used for analysis. Future manifest major versions
fail closed.

## Consequences

Every consuming run records the exact model ref. Existing mirror readers keep
working after writable reconciliation, while new code reads the manifest and
objects. Garbage collection and multi-file transactional storage are deferred.
