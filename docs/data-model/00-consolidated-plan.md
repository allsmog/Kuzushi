# Phase B — Consolidated Plan

Accepted scope from the 5 Phase A assessments + user review. Sibling docs:

- `_column-ownership.md` — ownership matrix
- `01-consolidation-and-naming.md` — A1
- `02-dead-code.md` — A2
- `03-migration-hygiene.md` — A3
- `04-constraints.md` — A4
- `05-denormalization.md` — A5

## Accepted this pass (v100 reset + Commit 2 + Commit 3)

### Migration mechanics (A3)

1. New `src/migrations/100_schema_reset.ts` replaces migrations 001–025 on fresh DBs.
2. `src/store.ts initDb()` gets:
   - `PRAGMA foreign_keys = ON` before `runMigrations`
   - Reset branch: inspect schema state; if `legacy-pre-v100`, close + rename `findings.sqlite3` → `findings.sqlite3.bak-v<N>-<UTC-ts>` with collision suffix + advisory lock, re-open fresh, run v100
   - Onto `SchemaStateError` on corrupt or `>v100`
3. `src/migrations/index.ts` registers v100 only.
4. `detectAndMarkLegacyDatabase` in `runner.ts` deleted (dead after reset branch).
5. Migrations 001–025 move to `src/migrations/_legacy/` for history; not imported.
6. Intel tables (`intel_documents` + `intel_fts`) stay ad-hoc for this pass. A3 assumed they were co-located with findings, but they live in a separate `.kuzushi/intel.sqlite3` file. Giving the intel DB its own migration trail is a follow-up refactor.

### Constraints (A4)

7. Fix `findings.verdict` CHECK to include `'by_design'` (live bug — `updateFindingVerdict()` throws today).
8. Add `CHECK` on 15 enum-like TEXT columns and 6 boolean-as-INTEGER columns per A4 §2.
9. Add 9 FKs with explicit `ON DELETE` per A4 §4 (CASCADE for per-finding children; SET NULL for pipeline_run_id on dynamic/crypto; SET NULL for trajectories.fingerprint; CASCADE for code_graph edges/paths → nodes; CASCADE for workspace_snapshots).
10. Reject composite UNIQUE on `(repo, ref, fingerprint)` — fingerprint is already sha256-deterministic (A4 §1b).

### Dead-column drops (A2 — HIGH confidence, user-approved)

11. Drop from `findings`: `confidence_signals_json` (H1), `calibrated_confidence` (H2), `evidence_chain_json` (H3), `composite_confidence` (H4).
12. Drop from `trajectories`: `task_id` (H7), `confidence` (H8), `repo` (H9).
13. Drop from `code_graph_{nodes,edges,paths}`: `run_id` (H10–H12).

### Denormalization (A5 — smaller fixes only)

14. Collapse `updateVerificationResult` + `updateVerificationCost` → single `updateVerification(db, fp, { result?, costOnly? })` with `db.transaction()`. Callers: `src/bus/workers/store-worker.ts:93,135,146,167`.
15. Same for `updatePocHarnessResult` + `updatePocHarnessCost` → `updatePocHarness(...)`.
16. Change `adjusted_score` write at `src/store.ts:195` to `NULL` when `finding.adjustedScore` is undefined (instead of coalescing to `finding.score`). Readers already handle nullable via `?? score`. (A5 correction: NOT dead — 7 legitimate adjust sites.)

### Type alignment (from A1/A4)

17. Add `'aborted'` to `PipelineRunStatus` at `src/store.ts:32–39` (A4 §3 "pipeline_runs.status").
18. Delete zombie `FindingRow` type in `src/types.ts:857` + its Zod schema at `src/schemas.ts:805` (A1 identified as uninstantiated).
19. Update `StoredFindingRecord`, `upsertFindingParams`, and `UPSERT_FINDING_SQL` to drop the 4 removed finding columns (calibrated_confidence, evidence_chain_json, composite_confidence, confidence_signals_json).
20. Delete dead functions: `_updateFindingCompositeConfidence`, `_updateRunAssertions`, `_updatePromptHash`, `_getRunAssertions`, `updateFindingCalibration`.
21. Tests updated: delete DB-level subtests for H2/H3 in `tests/confidence-calibration.test.ts`; delete e2e phase-1E composite_confidence checks in `tests/e2e/run-e2e.sh`.

## Deferred to separate follow-ups

### Feature audit PR (filed as follow-up issue)

Each of these is a half-shipped feature, not truly dead. Product decision required before drop vs wire:

- M1 `finding_assertions` — writer runs by default; reader is `_getRunAssertions` (dead). Assertion evidence accumulates on every scan with no consumer.
- M2 `crypto_behavioral_runs` — opt-in task generates detailed timing/statistical evidence; only reader is a test.
- M3 `dynamic_analysis_runs` — dynamic analysis writes live; `getDynamicAnalysisRun`/`getDynamicRunsForFinding` have zero callers; `findings.finding_metadata_json` stores dynamic-run-id pointers that nothing dereferences.
- M4 `workspace_snapshots` — `loadLatestSnapshot` is live, `saveSnapshot` is test-only (broken end-to-end).
- H5 `pipeline_runs.assertions_json`, H6 `pipeline_runs.prompt_hash` — `run-compare` CLI reads these; writers are dead `_`-prefixed. CLI always shows null for these fields.

For v100, **keep these columns/tables as-is** so we don't silently kill potential product features in a schema-cleanup PR.

### Refactor PR (follow-up)

- A1's 36 column renames + 26 TS renames — cosmetic; high churn, low bug-fix value.
- A5's 7 new `finding_*` side-tables (corroborations, suppressions, taint_steps, engines, evidence_steps, code_citations, controls) — real structural refactor; deserves its own PR with dedicated test coverage.
- `trajectories.cwes_json` → `trajectory_cwes(trajectory_id, cwe)` junction.
- `pipeline_runs.findings_json` rename to `scan_findings_json` for clarity (A5 recommended keep-but-rename).

## Commit plan (this pass)

**Commit 1** — `feat(db): v100 schema reset with FK enforcement and bug fixes`
- `src/migrations/100_schema_reset.ts` (NEW)
- `src/migrations/index.ts`, `src/migrations/runner.ts` edits
- `src/migrations/_legacy/` directory containing 001–025
- `src/store.ts` `initDb()` edits (PRAGMA, reset branch, helpers)
- `src/cli.ts` — remove 3 `createIntelTables` call sites
- `src/intel/store.ts` — keep `createIntelTables` exported (for tests), but no longer called in CLI boot path

**Commit 2** — `refactor(store): drop ghost columns, collapse split update paths`
- `src/store.ts` — drop 4 ghost column references; collapse split update paths; adjustedScore NULL fix
- `src/confidence-calibration.ts` — delete `updateFindingCalibration`
- `src/bus/workers/triage-worker.ts` — drop calibration DB-write call site
- `src/bus/workers/store-worker.ts` — update callers of the collapsed update functions
- `src/types.ts` — add `'aborted'` to `PipelineRunStatus`; delete zombie `FindingRow`
- `src/schemas.ts` — delete zombie `FindingRowSchema`

**Commit 3** — `test: update storage tests for v100 schema`
- `tests/migrations/schema-reset.test.ts` (NEW)
- `tests/store.test.ts` — drop ghost-column assertions
- `tests/confidence-calibration.test.ts` — drop DB-level calibration subtests
- `tests/intel/store.test.ts` — remove `createIntelTables` call; rely on `initDb` to create them
- `tests/e2e/run-e2e.sh` — drop composite_confidence phase-1E checks
