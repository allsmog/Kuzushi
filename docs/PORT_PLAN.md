# Kuzushi Current Port Contract

This file used to be the long upstream-port work ledger. The implementation is
now Rust-native and v3-backed, so the old task log was removed. Keep this file
as a small compatibility anchor for guard scripts that verify public identity,
bounded contexts, and deferred-surface policy.

Upstream reference: `upstream-codex`. Current ownership and boundaries live in
`docs/architecture/kuzushi-boundaries.md`, `docs/architecture/v3-persistence.md`,
`docs/architecture/v3-identity.md`, `docs/architecture/v3-plugin-sandbox.md`,
and `docs/architecture/kuzushi-artifacts.md`.

## Public Identity

- binary: `kuzushi`
- alias: `kz`
- prompt: `kuzushi>` or `kz>`
- header: `KUZUSHI`
- state directory: `.kuzushi/`

## Required Contexts

- `context`
- `attack_surface`
- `threat_model`
- `modules`
- `recommender`
- `scanners`
- `findings`
- `proof`
- `triage`
- `verify`
- `patch`
- `report`
- `run_trace`
- `run_lifecycle`
- `failure`
- `ui_*`

## Deferred Surfaces

Deferred modules are registered for exact invocation and should not become
ordinary recommender suggestions. `systems-hunt:*` entries are internal DAG
nodes. `carlini-threat-hunt`, `uaf-hunt`, and `classifier-gate` are hidden
exact-invocation plugin-backed or specialist surfaces unless their owning
executor explicitly promotes a user-facing action.

Guardrails should keep these properties visible:

- hidden exact-invocation plugin-backed tools stay hidden from broad catalogs;
- internally registered DAG nodes stay out of recommender output;
- optional plugin packages remain optional dependencies.

## Phase Ledger

The old phase ledger is complete and deleted. Current phase/state-machine
truth is in Rust application state and the v3 architecture docs:

- v3 source snapshots and CAS objects own code-derived facts;
- the append-only event log owns human decisions, rekeys, verification, patch
  attempts, and audit events;
- SQLite is a disposable projection with an applied-sequence watermark;
- run directories are replay/export bundles whose per-run lifecycle source is
  the versioned, hash-linked `items.jsonl` stream;
- domain sidecars such as context, attack-surface, findings, recommendations,
  strategy, or proof are producer-declared artifacts, not synthesized
  canonical snapshot leaves.
