# 01 — Consolidation & Naming (Agent 1)

**Dimension:** DB↔TS type shape + naming conventions.
**Scope:** `src/types.ts`, `src/scanners/types.ts`, `src/agents/types.ts`,
`src/bus/events.ts`, `src/schemas.ts`, all `*Row` interfaces and their
`rowTo*()` mappers across the per-module stores, plus the 25 migration files.
**Hands off to others:** table splits/merges (A5), CHECK/FK/UNIQUE
(A4), migration mechanics (A3), dead-column drops (A2).

Every claim below has an evidence anchor. Rename tables at the end compile
every proposed rename into a single flat list.

---

## 1. Critical assessment

### 1.1 The "Finding" concept has four coexisting TS shapes

One logical entity — a finding — is modeled four different ways and they
disagree about which fields are first-class, which are optional, and which
are serialized vs. structured:

| # | Type | File:line | Purpose | Representation of `verificationSteps` | Representation of `fixPatch` |
|---|------|-----------|---------|----------------------------------------|------------------------------|
| 1 | `Finding` | `src/scanners/types.ts:45` | task output (in-memory, pre-triage) | absent — triage owns it | absent |
| 2 | `TriageResult` | `src/types.ts:134` | LLM triage output (camelCase) | `verificationSteps: string[]` (`types.ts:145`) | `fixPatch: string \| null` (`types.ts:146`) |
| 3 | `FindingRow` | `src/types.ts:857` | SQLite row *type* | `verificationSteps: string` (serialized JSON) (`types.ts:870`) | `fixPatch: string \| null` (`types.ts:871`) |
| 4 | `StoredFindingRecord` | `src/store.ts:58` | result of `getActionableFindings()` rowTo-mapper output | `verificationSteps: string[]` (`store.ts:71`) | `fixPatch: string \| null` (`store.ts:72`) |

Observations:

- `FindingRow` and `StoredFindingRecord` are the **same table** at different
  hydration levels. `FindingRow` keeps the raw JSON-serialized blobs as
  `*Json: string` fields (`types.ts:872, 877, 893, 894, 896`);
  `StoredFindingRecord` already parsed them into `Record<string,unknown>` /
  array shapes (`store.ts:73, 94, 98, 100-105`). **They are never used in
  the same call path.** `StoredFindingRecord` is what `rowTo*()` in
  `getActionableFindings()` returns (`store.ts:864-929`); `FindingRow`
  has a Zod schema in `schemas.ts:805` but no codepath actually instantiates
  it — grep shows only the schema definition and type re-export. **`FindingRow`
  is a zombie type.**

- `StoredFindingRecord` has **zero overlap** with `Finding` (`scanners/types.ts:45`):
  the former is a persistence record (verdict, confidence, verify_*, poc_*), the
  latter is a scanner output (score, evidence, subcategory, taintPath,
  engineProvenance). Yet callers that consume "a triaged finding" pass
  around ad-hoc merges of both — e.g. `report.ts`, `report-markdown.ts`,
  `report-sarif.ts` all reconstruct something resembling a combined shape
  from multiple sources. There is no canonical `StoredFinding` that
  carries both pre-triage and post-triage data.

- `StoredFindingRecord` **silently drops**
  `scannerConfidence`, `subcategory`, `likelihood`, `impact`, `cwe`,
  `score`, `reachable`, `evidence` — fields that live on `Finding`
  (`scanners/types.ts:49-72`) but have no column on `findings`. That
  data exists only in `pipeline_runs.findings_json` snapshots
  (`store.ts:1139-1145`). Anyone who loads a finding via
  `getStoredFinding()` (`store.ts:1018`) **cannot see the scanner's
  original score or CWE list** unless they also hold the original
  `Finding` object in memory. This is invisible to the type system.

- `TriageResult.calibratedConfidence` (`types.ts:159`) and
  `TriageResult.compositeConfidence` (`types.ts:161`) exist on the TS type
  and on the DB (`composite_confidence` col added in migration 013,
  `calibrated_confidence` added in migration 010). But neither appears in
  `StoredFindingRecord` (`store.ts:58-108`); the `getActionableFindings`
  SELECT never reads them (`store.ts:782-814`). They are write-only at
  the hydration boundary.

### 1.2 TriageResult's `evidenceChain` + `evidence_chain_json` column are write-only in one path

- Migration 010 adds `evidence_chain_json` column (`010_add_calibration_schema.ts:25`).
- `confidence-calibration.ts:222-238` writes it under a condition.
- `StoredFindingRecord` never reads it. `getActionableFindings()` never
  SELECTs it. Agent 2 will flag it as near-dead; Agent 5 may want to
  roll it into `triage_details_json`. From Agent 1's lens: the type
  `EvidenceStep[]` (`types.ts:98`) exists with no mapper from this column,
  so the column and the type are effectively unconnected.

### 1.3 Verdict enum is already out of sync between code and schema

- `Verdict` in `src/types.ts:87` = `"tp" | "fp" | "needs_review" | "by_design"`.
- CHECK constraint in `001_initial_schema.ts:22` =
  `('tp','fp','needs_review')` — **excludes `'by_design'`**.
- `getVerdictCounts()` (`store.ts:625-643`) includes `by_design: 0` in the
  initial count shape and reads back whatever the DB returns.
- `updateFindingVerdict()` (`store.ts:1033-1044`) declares the param as
  `"tp" | "fp" | "needs_review" | "by_design"`.

→ Inserting `by_design` does not currently error only because SQLite's
CHECK enforcement is subtle (it does enforce: inserts actually do fail —
this is a latent bug that Agent 4 should confirm with a test). Either
way, the constraint-literal and the TS type are out of sync, and have
been since whichever commit added `"by_design"` to the TS enum.

### 1.4 Three parallel "verdict" enums that mean different things

Confusingly named:

| Enum | Domain | Values |
|---|---|---|
| `Verdict` (`types.ts:87`) | AI triage verdict | `"tp" \| "fp" \| "needs_review" \| "by_design"` |
| `ProofVerdict` (`types.ts:185`) | Exploitability verification proof | `"exploited" \| "blocked_by_security" \| "out_of_scope" \| "false_positive"` |
| `CryptoBehavioralVerdict` (`crypto-behavioral/types.ts:9`) | Crypto behavioral test verdict | `"vulnerable" \| "secure" \| "inconclusive" \| "error"` |

In the DB they collide: `findings.verdict` is `Verdict`,
`dynamic_analysis_runs.status` is a fourth enum
(`"confirmed" \| "interesting" \| "rejected" \| "error"` —
`017_add_dynamic_and_patch_persistence.ts:28`),
`patch_results.status` is a fifth enum
(`"APPLY_FAILED" \| "BUILD_FAILED" \| ... \| "UNKNOWN"` —
`017_add_dynamic_and_patch_persistence.ts:62`, extended by 020),
`crypto_behavioral_runs.verdict` is stored as free TEXT
(`018_add_crypto_behavioral_runs.ts:11` — **no CHECK constraint at
all**, unlike the others).

Agent 4 must draw the CHECK matrix. But from a **naming** standpoint,
all three LLM verdicts should use the suffix `*Verdict` (consistent) and
the status enums for `dynamic_analysis_runs` / `patch_results` should
**not** be called `status` if they carry verdict semantics. Today
`dynamic_analysis_runs.status` is semantically a verdict; calling it
`status` conflicts with `pipeline_runs.status` which is a genuine
lifecycle state. Proposed in §4: rename `dynamic_analysis_runs.status` →
`verdict`, rename `patch_results.status` → `verdict` (since every value
is an outcome, not a lifecycle), and reserve `status` for `pipeline_runs`.

### 1.5 SELECT-alias style reveals the mismatch

Across `store.ts` there are **over 50 `<snake_case> as <camelCase>`
aliases** in prepared statements. A sample:

- `src/store.ts:372-376`: `verification_steps as verificationSteps, fix_patch as fixPatch, triage_cost_usd as triageCostUsd, triage_details_json as triageDetailsJson`
- `src/store.ts:578-584`: the seven verify_* aliases
- `src/store.ts:783-813`: the 36-column `getActionableFindings` SELECT

This is the canonical smell that the ORM-less layer is papering over a
type boundary. Two fixes are possible:

1. **Accept the alias style** and make it the house convention: every
   SELECT aliases snake→camel, every INSERT binds camel inputs to
   snake placeholders.
2. **Make the row-types snake_case** and let the mapper do the rename
   in one place per table.

Today's code is inconsistent: `code_graph` (`store.ts`) reads raw
`Record<string,unknown>` and indexes with bracket notation (`row["file_path"]`
— `code-graph/store.ts:243`); `dynamic_analysis_runs` uses explicit
snake_case row types (`DynamicAnalysisRunRow` —
`store/dynamic-analysis.ts:5-29`); `findings` uses SELECT aliasing
inline; `workspaces` uses snake_case row types
(`workspace/manager.ts:103-110`); `trajectories` uses snake_case row types
(`trajectory-memory.ts:19-33`). **Four different styles inside one
project.** Proposed: lock on **style 2** (snake_case row types + one
`rowTo*` mapper per table, colocated). Rationale in §3.

### 1.6 `FindingRow` fields are partial-camelCased strings of JSON

Look at the schizophrenia of `FindingRow` (`types.ts:857-899`):

- `taskId`, `fingerprint`, `repo`, `ref`, `ruleId`, `filePath`,
  `startLine`, `severity`, `message`, `verdict`, `confidence`,
  `rationale` — camelCase, typed normally.
- `verificationSteps: string` — this is not a `string[]`; it's a JSON
  blob (`types.ts:870`).
- `triageDetailsJson?: string | null` — `*Json` suffix communicates this
  *is* JSON.
- `confidenceSignalsJson?`, `taintPathJson?`, `engineProvenanceJson?` —
  same.
- BUT `verificationSteps` does not follow the same `*Json` convention
  despite being JSON. Proposed: either rename field → `verificationStepsJson`
  (column stays `verification_steps` — rename to `verification_steps_json`
  too), or flip the `StoredFindingRecord`-style where the type presents
  parsed arrays and hides the JSON form.

### 1.7 The `scanner` vs `task_id` rename is partially done

- Migration 002 (`002_add_scanner_column.ts`) — file says "rename to task_id"
  in its docstring but actually creates a `task_id` column; migration 024
  (`024_rename_scanner_to_task_id.ts:1-32`) cleans up stale `scanner`
  columns from older DBs.
- TS type `ScannerId` is aliased to `TaskId` (`scanners/types.ts:5`):
  `export type ScannerId = TaskId;`. Same for `ScannerConfig = TaskConfig`.
- `ScanFindingEvent.scannerId` (`bus/events.ts:186`) still uses the old name
  at the event boundary (and the scan worker passes `scannerId: taskId`
  at `scan-worker.ts:108`).

→ `ScannerId`/`ScannerConfig` are legacy aliases. `scannerId` on the scan event
is an inconsistency with the rest of the codebase. Proposed: drop
`ScannerId`/`ScannerConfig` aliases; rename event payload field
`scannerId` → `taskId`. Cross-cutting: A2 should confirm zero call sites
still rely on the alias after rename.

### 1.8 `blame`/`introducedIn` exist both on `Finding` and in `finding_metadata_json`

- `Finding.blame` and `Finding.introducedIn` declared at
  `scanners/types.ts:70, 72`.
- Stored only inside the JSON blob `finding_metadata_json`
  (`store.ts:1316-1330`).
- `StoredFindingRecord` re-exposes them (`store.ts:106-107`) by
  re-parsing the metadata JSON at `store.ts:924-927`.

→ The fields are flat TS but nested JSON. Agent 5 may want to hoist
them into first-class columns (`blame_sha_commit`, `blame_author`,
`blame_date_at`, `blame_summary`, `introduced_in_sha`). From naming
alone the current state is fine because we have exactly one hydration
path; but worth flagging since `findingMetadata` is one of the 12
opaque JSON blobs the plan calls out.

### 1.9 Timestamp naming is inconsistent

All tables today end timestamp columns in `_at` **except**:

- `dynamic_analysis_runs.execution_duration_ms` (`_ms`, fine — duration)
  (`017_add_dynamic_and_patch_persistence.ts:39`).
- `crypto_behavioral_runs.execution_duration_ms` (`_ms`, fine)
  (`018_add_crypto_behavioral_runs.ts:21`).
- `findings.poc_run_duration_ms` (`_ms`, fine)
  (`007_add_poc_execution_columns.ts:16`).
- `findings.mean_a_ns`, `mean_b_ns` (`_ns`, nanoseconds — inconsistent
  unit with other durations in the same schema that use ms; this is on
  `crypto_behavioral_runs` not `findings` — correction:
  `018_add_crypto_behavioral_runs.ts:24-25`).
  Mean times in nanoseconds is accurate for timing-attack detection,
  so `_ns` is correct; **but we should establish in the rulebook
  that `_ns` and `_ms` both exist and the rule is "suffix matches the
  unit stored".** The current inconsistency is that the rule has not
  been written down.

TS-side camelCase equivalents: `createdAt`, `updatedAt`,
`lastAccessedAt`, `completedAt`, `ingestedAt`, `startedAt` — all `*At`,
correct. No drift. **But**: `CryptoBehavioralRun.createdAt` and
`.updatedAt` are declared as `string` (`crypto-behavioral/types.ts:84-85`)
in the ISO-8601 convention; `DynamicAnalysisRun.createdAt` /
`.updatedAt` are `string` too (`types.ts:265-266`); `TrajectoryRecord.createdAt`
is `string` (`trajectory-memory.ts:32`). Consistent. OK.

### 1.10 Cost naming split

- TS-side: `triageCostUsd`, `verifyCostUsd`, `pocHarnessCostUsd`,
  `costUsd` (dynamic run, patch run, crypto run).
- DB-side: `triage_cost_usd`, `verify_cost_usd`, `poc_harness_cost_usd`,
  `cost_usd` (per-run tables), `total_cost_usd` (pipeline_runs).
- Config-side: `multiStrategyBudgetUsd`, `multiStrategyPerStrategyBudgetUsd`,
  `costBudgetUsd`, `dynamicPerFindingBudgetUsd`,
  `multiStrategyTimeoutMs`, `cryptoBehavioralPerFindingBudgetUsd`.

Consistent: every monetary value uses `*CostUsd` or `*BudgetUsd`. The
only ambiguity is `pipeline_runs.total_cost_usd` vs the per-stage
`triage_cost_usd` / `verify_cost_usd` / `poc_harness_cost_usd` on
`findings`. Since A5 is probably extracting these into a `finding_costs`
side-table, Agent 1's naming rule is: "`<stage>_cost_usd` inside any
row that carries a single cost; `total_cost_usd` only on aggregator
rows." Defer structural decision to A5.

### 1.11 `updatePocHarnessResult` has `poc_run_*` and `poc_harness_*` side by side

`store.ts:1474-1512` updates 12 columns in one statement — but they're
split into two naming prefixes (`poc_harness_*` for generation state,
`poc_run_*` for execution state). The TS side
(`PocHarnessResult` in `types.ts:215-237`) uses yet a third prefix:
`pocExec*` for execution (`pocExecExitCode`, `pocExecStdout`,
`pocExecStderr`, `pocExecVerdict`, `pocExecDurationMs`). So the same
concept is:

- Column name: `poc_run_exit_code`.
- FindingRow TS field name (`types.ts:887`): `pocRunExitCode`.
- StoredFindingRecord field name (`store.ts:88`): `pocRunExitCode`.
- PocHarnessResult field name (`types.ts:226`): `pocExecExitCode`.
- RawPocHarnessOutputSchema (`schemas.ts:240`): `pocExecExitCode`.

→ `poc_run_*` vs `pocExec*`. Two different names for the same value
crossing the DB↔TS boundary. Proposed: pick one. `*_exec_*` /
`*Exec*` is slightly clearer (generation is `harness`, execution is
`exec`) — rename DB columns `poc_run_*` → `poc_exec_*` to match TS.

### 1.12 `verify_exploitable` stored as INTEGER 0/1

`findings.verify_exploitable` is declared `INTEGER`
(`005_add_verification_columns.ts:13`), written as `1/0`
(`store.ts:1444`), read back and coerced in `store.ts:611`:
`exploitable: row.verifyExploitable === 1`. TS type is
`VerificationResult.exploitable: boolean` (`types.ts:190`). So `FindingRow.verifyExploitable`
is `number | null` (`types.ts:873`) and `StoredFindingRecord.verifyExploitable`
is also `number | null` (`store.ts:74`). The boolean↔integer conversion
bleeds into consumers. Proposed (naming rule): any column representing
a boolean must carry a `*_flag` suffix. Rename
`verify_exploitable` → `verify_exploitable_flag`. `poc_harness_parsed`,
`poc_harness_skipped`, `trajectories.was_correct`,
`finding_assertions.passed`, `code_graph_paths.has_sanitizer` all get the
same treatment. Yes, verbose; but it removes ambiguity about whether
the column is a nullable boolean or a tri-state integer. **A4 must
still CHECK `IN (0,1)`.**

### 1.13 `pipeline_runs.head_ref` has no pair column

`findings` has `repo`, `ref` (the fingerprint-anchoring ref). Every scan
is tied to a commit, but `ref` may not always be the scanned commit —
`pipeline_runs.head_ref` (`021_add_incremental_scanning_support.ts:13`)
stores the head ref at scan time. Mixing the two: `findings.ref` is set
once per fingerprint upsert, `pipeline_runs.head_ref` is updated post-hoc.
Naming — `findings.ref` should really be `findings.scan_ref` or
`findings.fingerprint_ref` to distinguish it. Proposed: **rename
`findings.ref` → `findings.scan_ref`**. Low risk (every read is
aliased/explicit).

### 1.14 Assertions table names are partial snake_case

`finding_assertions` (`015_add_assertion_tracking.ts:23-35`):
- `assertion_name TEXT`, `passed INTEGER`, `score REAL`, `weight REAL`,
  `reason TEXT`, `created_at TEXT`.
- No `updated_at`. No `fingerprint_*` prefix on anything.

The row type as consumed by `_getRunAssertions` (`store.ts:1759-1788`)
re-aliases `assertion_name` → `assertionName`. This fits the rename-in-
SELECT pattern. Fine. But since A2 flags this function as unused
(underscore prefix = dead-code marker), the whole reader path may die.
Defer.

### 1.15 JSON-blob column suffix is mostly-but-not-consistently `_json`

Columns that ARE `*_json`:

| Column | Migration |
|---|---|
| `findings.triage_details_json` | 004 |
| `findings.corroboration_json` | 012 |
| `findings.suppression_json` | 012 |
| `findings.confidence_signals_json` | 013 |
| `findings.taint_path_json` | 016 |
| `findings.engine_provenance_json` | 016 |
| `findings.finding_metadata_json` | 017 |
| `findings.evidence_chain_json` | 010 |
| `pipeline_runs.config_json` | 001 |
| `pipeline_runs.scan_opts_json` | 001 |
| `pipeline_runs.findings_json` | 001 |
| `pipeline_runs.context_json` | 008/009 |
| `pipeline_runs.metrics_json` | 014 |
| `pipeline_runs.assertions_json` | 015 |
| `dynamic_analysis_runs.seed_inputs_json` | 017 |
| `dynamic_analysis_runs.metadata_json` | 017 |
| `patch_results.history_json` | 017 |
| `crypto_behavioral_runs.metadata_json` | 018 |
| `code_graph_nodes.metadata_json` | 019 |
| `intel_documents.metadata_json` | ad-hoc |
| `workspaces.targets_json` | 025 |
| `workspaces.metadata_json` | 025 |
| `workspace_snapshots.snapshot_json` | 025 |
| `trajectories.cwes_json` | 011 |
| `trajectories.steps_json` | 011 |

Columns that hold JSON but are **not** suffixed:

- `findings.verification_steps` — stores a JSON array string
  (`store.ts:201`: `safeJsonStringify(triage.verificationSteps)`). Should be
  `verification_steps_json`.
- `findings.verify_preconditions` — JSON array string
  (`store.ts:1448`: `safeJsonStringify(result.preconditions)`). Should be
  `verify_preconditions_json`.
- `code_graph_paths.path_node_ids` — stores `JSON.stringify(nodeIds)`
  (`code-graph/store.ts:115`). Should be `path_node_ids_json`.
- `code_graph_paths.path_edge_ids` — same. `path_edge_ids_json`.
- `code_graph_paths.sanitizer_nodes` — stores
  `JSON.stringify(sanitizerNodeIds)` (`code-graph/store.ts:118`). Should
  be `sanitizer_node_ids_json`.

TS-side `*Json` suffix matches on the type side
(`triageDetailsJson`, `confidenceSignalsJson`, etc). Once columns are
renamed the TS suffix stays consistent.

### 1.16 ID column naming is inconsistent

| Table | PK column | Pattern |
|---|---|---|
| `findings` | `fingerprint` | **not `id`**, intentionally — fingerprint is the natural key |
| `pipeline_runs` | `run_id` | `<tbl_short>_id` |
| `trajectories` | `id` | generic `id` |
| `finding_assertions` | `id` (AUTOINCREMENT) | generic `id` |
| `dynamic_analysis_runs` | `dynamic_run_id` | `<tbl_short>_id` |
| `patch_results` | `patch_run_id` | `<tbl_short>_id` |
| `crypto_behavioral_runs` | `run_id` | **collides conceptually with `pipeline_runs.run_id`** — see 1.17 |
| `code_graph_nodes` | `node_id` | `<tbl_short>_id` |
| `code_graph_edges` | `edge_id` | `<tbl_short>_id` |
| `code_graph_paths` | `path_id` | `<tbl_short>_id` |
| `workspaces` | `id` | generic `id` |
| `workspace_snapshots` | `id` (AUTOINCREMENT) | generic `id` |
| `intel_documents` | `id` | generic `id` |
| `calibration_weights` | `(step_type, rule_family)` composite | composite PK, no `id` |

Two styles coexist: `<prefix>_id` and plain `id`. FK columns
(`pipeline_run_id` on dynamic/patch/crypto; `workspace_id` on
snapshots; `from_node_id`/`to_node_id` on edges) consistently use
`<referenced_table_singular>_id`.

Proposed:
- **PK: always `<table_singular>_id`** (e.g. `workspaces.workspace_id`,
  `workspace_snapshots.snapshot_id`, `intel_documents.document_id`,
  `trajectories.trajectory_id`, `finding_assertions.assertion_id`).
  Rationale: eliminates ambiguity when joins alias columns; matches
  existing `node_id`/`edge_id`/`path_id`/`run_id`/`patch_run_id` style.
- **`findings.fingerprint` stays** (natural key; has special semantics).
- **`crypto_behavioral_runs.run_id` renamed to `crypto_run_id`** to
  disambiguate from `pipeline_runs.run_id` (which is a *different*
  concept). Explicit winner.

### 1.17 `crypto_behavioral_runs.run_id` vs `pipeline_run_id` confusion

On `crypto_behavioral_runs`:

```
run_id          TEXT PRIMARY KEY   -- the crypto-run's own ID
pipeline_run_id TEXT               -- FK to pipeline_runs.run_id
```

TS interface `CryptoBehavioralRun.runId`
(`crypto-behavioral/types.ts:60`) refers to the crypto-run ID, and
`pipelineRunId` refers to the parent pipeline run. In
`insertCryptoBehavioralRun` (`store/crypto-behavioral.ts:45`) the bind
order is `runId, pipelineRunId` — correct. But `dynamic_analysis_runs`
uses `dynamic_run_id` for the same concept; `crypto_behavioral_runs`
just calls it `run_id`, which is exactly the column name used on
`pipeline_runs`. This is trivially a foot-gun waiting to happen in any
future JOIN.

Rename: `crypto_behavioral_runs.run_id` → `crypto_run_id` (column);
`CryptoBehavioralRun.runId` → `CryptoBehavioralRun.cryptoRunId` (field).

### 1.18 `code_graph_paths.path_node_ids` plural in a singular column name

Plural is fine when the column literally holds a list. But then the
JSON-suffix rule (1.15) means it should be `path_node_ids_json`. Same
for `sanitizer_nodes` → `sanitizer_node_ids_json`. Both contain JSON
arrays of strings per `code-graph/store.ts:115-118`.

### 1.19 `dynamic_analysis_runs.execution_*` vs `poc_run_*` fragmentation

`dynamic_analysis_runs` has:
- `execution_exit_code`, `execution_stdout`, `execution_stderr`,
  `execution_verdict`, `execution_duration_ms`
  (`017_add_dynamic_and_patch_persistence.ts:32-37`).

`findings` PoC execution has:
- `poc_run_exit_code`, `poc_run_stdout`, `poc_run_stderr`,
  `poc_run_verdict`, `poc_run_duration_ms`
  (`007_add_poc_execution_columns.ts:10-16`).

`crypto_behavioral_runs` has:
- `execution_exit_code`, `execution_verdict`, `execution_stdout`,
  `execution_stderr`, `execution_duration_ms`
  (`018_add_crypto_behavioral_runs.ts:13-17`).

Same semantic fields, two different prefixes. Proposed:
**standardize on `exec_*`** (short, unambiguous, matches
`PocHarnessResult.pocExec*` camelCase convention used TS-side):

- `execution_exit_code` → `exec_exit_code`
- `execution_stdout` → `exec_stdout`
- `execution_stderr` → `exec_stderr`
- `execution_verdict` → `exec_verdict`
- `execution_duration_ms` → `exec_duration_ms`
- `findings.poc_run_*` → `findings.poc_exec_*`

This also aligns with 1.11.

### 1.20 Field-vs-column divergence in `trajectories`

`TrajectoryRecord` (`trajectory-memory.ts:19-33`) is an **odd exception**
in the codebase: its fields are **already snake_case**:

```ts
export interface TrajectoryRecord {
  id: string;
  rule_id: string;           // <— snake
  cwes_json: string;         // <— snake
  task_id: string;           // <— snake
  ...
  was_correct: number | null;
  steps_json: string;
  ...
}
```

No other store mapper preserves snake_case. Every read/write passes the
raw row through as `TrajectoryRecord` (`trajectory-memory.ts:213-289`).
So the type is effectively a row type disguised as a domain type.

Consistency fix: either
- **(A)** split into snake_case `TrajectoryRow` and camelCase
  `Trajectory`, with a `rowToTrajectory()` mapper; or
- **(B)** accept this as the single exception and document it.

§3 proposal is (A). Uniformity wins.

### 1.21 `Workspace` hides a `workspaces.updated_at` column it never reads

`workspaces` table has seven columns:
`id, name, targets_json, created_at, last_accessed_at, metadata_json, updated_at`
(migration 025 creates six; `manager.ts:60` writes `updated_at` in
`update()` but the SELECT in `manager.ts:23, 30, 44` does `SELECT *`,
so `updated_at` comes back; but `WorkspaceRow`
(`manager.ts:103-110`) only types six columns — `updated_at` isn't
declared on the row type even though SQL touches it). `Workspace` type
(`workspace/types.ts:2-15`) exposes only five. The seventh
(`updated_at`) is write-only-plus-ignored, like a ghost.

Fix: Add `updatedAt` to `Workspace` and `WorkspaceRow`, or drop the
column. Agent 2 should flag liveness; Agent 1 position is "either read
it or kill it; do not have a write-only column".

### 1.22 Event payloads use camelCase already — the cleanest layer

`src/bus/events.ts` is entirely camelCase TS. No drift. Only nuance is
`ScanFindingEvent.scannerId` (see 1.7) using the legacy name. Rename to
`taskId`.

`PipelineStats` (`bus/events.ts:25-78`) uses `*CostUsd` for monetary
and `*Ms` where applicable. Clean.

---

## 2. Canonical `Finding` shape

Current overlapping types collapse to two canonical TS interfaces
(naming only — A5 owns whether the DB shape mirrors them):

```ts
/** The canonical scanner output: facts about a vulnerability candidate. */
export interface Finding {
  // Identity
  taskId: TaskId;
  fingerprint: string;
  // Location
  ruleId: string;
  filePath: string;
  startLine: number;
  // Severity / classification (scanner-provided)
  severity: string;        // lowercase 'critical'|'high'|'medium'|'low'|'info'
  message: string;
  cwe: string[];
  subcategory: string[];
  // Scoring
  score: number;                // 0-100 scanner raw score
  adjustedScore?: number;       // post-provenance boost/penalty
  // Confidence / reachability
  scannerConfidence: string;    // 'high'|'medium'|'low' (scanner-native)
  likelihood: string;
  impact: string;
  reachable?: "true" | "false" | "unknown";
  // Evidence
  evidence?: string | null;
  taintPath?: TaintPathStep[];
  proofState?: ProofState;
  engineProvenance?: EngineProvenance[];
  corroboratingSignals?: CorroboratingSignal[];
  suppressionReasons?: SuppressionReason[];
  // Git attribution
  blame?: BlameInfo;
  introducedIn?: string;
}
```

Nothing changes structurally — this is the existing
`src/scanners/types.ts:45` shape with the same fields. The point is
to declare it canonical and delete the fake cousins:

**Delete entirely**:
1. `FindingRow` (`src/types.ts:857-899`) — replace with a generated
   `FindingRow` alongside the `rowToFinding()` mapper in `store/findings.ts`
   (A5 may relocate — this is A1 saying the top-level `types.ts`
   shouldn't own a DB-shape type).
2. `FindingRowSchema` (`src/schemas.ts:805-848`) — only useful if we
   actually runtime-validate DB rows. We don't anywhere. Kill the
   schema. If we ever want it back, re-derive from the new row type.

**Merge into one**:
3. `StoredFindingRecord` (`src/store.ts:58-108`) and the anonymous row type
   at `src/store.ts:820-862` (inline in `getActionableFindings`). Replace
   with a single exported `StoredFinding` that represents
   "Finding + TriageResult + VerificationResult + PocHarnessResult"
   flattened. Shape (naming only — A5 decides extraction):

```ts
/** A fully-hydrated persisted finding: scan output + triage + verify + poc. */
export interface StoredFinding {
  // ── Finding (scan output) ──────────────────────────────────
  taskId: TaskId;
  fingerprint: string;
  repo: string;
  scanRef: string;                 // was `ref` (see 1.13)
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  adjustedScore: number | null;
  taintPath?: TaintPathStep[];
  proofState?: ProofState;
  engineProvenance?: EngineProvenance[];
  corroboratingSignals: CorroboratingSignal[];
  suppressionReasons: SuppressionReason[];
  findingMetadata?: FindingMetadata;

  // ── Triage ─────────────────────────────────────────────────
  verdict: Verdict;
  confidence: number;
  rationale: string;
  verificationSteps: string[];
  fixPatch: string | null;
  triageDetails: Record<string, unknown> | null;
  triageCostUsd: number | null;
  compositeConfidence: number | null;
  calibratedConfidence: number | null;

  // ── Verification ───────────────────────────────────────────
  verifyExploitableFlag: number | null;   // see 1.12
  verifyPocPayload: string | null;
  verifyPocDescription: string | null;
  verifyAttackVector: string | null;
  verifyPreconditions: string[];
  verifyConfidence: number | null;
  verifyCostUsd: number | null;

  // ── PoC harness ────────────────────────────────────────────
  pocHarnessPath: string | null;
  pocHarnessLanguage: string | null;
  pocHarnessParsedFlag: number | null;
  pocHarnessParseError: string | null;
  pocHarnessSkippedFlag: number | null;
  pocHarnessSkipReason: string | null;
  pocHarnessCostUsd: number | null;

  // ── PoC execution (renamed from poc_run_* → poc_exec_*) ────
  pocExecExitCode: number | null;
  pocExecStdout: string | null;
  pocExecStderr: string | null;
  pocExecVerdict: PocExecVerdict | null;
  pocExecDurationMs: number | null;

  // ── Derived-from-triage-details (unchanged, parsed once) ──
  codeCitations?: CodeCitation[];
  attackPath?: AttackPathAnalysis;
  assumptions?: string[];
  controls?: SecurityControl[];
  blindspots?: string[];
  sourceThreatIds?: string[];

  // ── Derived-from-metadata-json ─────────────────────────────
  blame?: BlameInfo;
  introducedIn?: string;

  createdAt: string;
  updatedAt: string;
}
```

This is a single hydrated view. The `*Flag` suffix on
`verifyExploitableFlag`, `pocHarnessParsedFlag`, `pocHarnessSkippedFlag`
makes the 0/1 integer nature explicit (1.12).

`TriageResult`, `VerificationResult`, `PocHarnessResult`, `DynamicAnalysisRun`,
`PatchResult`, `CryptoBehavioralRun` all **stay**: they are domain
objects emitted by their own stages and consumed by the store worker.
Their fields are already camelCase and already named consistently;
rename only those listed in §4.

---

## 3. Row-type strategy

**Rule: one `<Entity>Row` interface per table, colocated with the mapper
`rowTo<Entity>()` that parses it.** Snake_case fields on the row type,
camelCase fields on the domain type. The mapper is the single boundary.

### 3.1 Proposed layout (naming + location only — A5 owns final file layout)

| Table | Row type | Mapper | Domain type | File |
|---|---|---|---|---|
| `findings` | `FindingRow` | `rowToStoredFinding` | `StoredFinding` | `src/store/findings.ts` (new) |
| `pipeline_runs` | `PipelineRunRow` | `rowToPipelineRun` | `PipelineRunRecord` (already local) | `src/store/pipeline-runs.ts` (extract from `store.ts`) |
| `trajectories` | `TrajectoryRow` | `rowToTrajectory` | `Trajectory` (rename from `TrajectoryRecord`, camelCase) | `src/trajectory-memory.ts` |
| `finding_assertions` | `FindingAssertionRow` | `rowToFindingAssertion` | `FindingAssertion` (new — split from inline anonymous in `_getRunAssertions`) | `src/store/assertions.ts` (new) |
| `dynamic_analysis_runs` | `DynamicAnalysisRunRow` | `rowToDynamicAnalysisRun` | `DynamicAnalysisRun` | `src/store/dynamic-analysis.ts` (already correct) |
| `patch_results` | `PatchResultRow` | `rowToPatchResult` | `PatchResult` | `src/store/patch-results.ts` (already correct) |
| `crypto_behavioral_runs` | `CryptoBehavioralRunRow` | `rowToCryptoBehavioralRun` | `CryptoBehavioralRun` | `src/store/crypto-behavioral.ts` (already correct) |
| `code_graph_nodes` | `CodeGraphNodeRow` (new; explicit instead of `Record<string,unknown>`) | `rowToCodeGraphNode` | `CodeGraphNode` | `src/agents/tasks/code-graph/store.ts` |
| `code_graph_edges` | `CodeGraphEdgeRow` (new) | `rowToCodeGraphEdge` | `CodeGraphEdge` | same |
| `code_graph_paths` | `CodeGraphPathRow` (new) | `rowToCodeGraphPath` | `CodeGraphPath` | same |
| `workspaces` | `WorkspaceRow` (add `updated_at`) | `rowToWorkspace` | `Workspace` (add `updatedAt`) | `src/workspace/manager.ts` (or break out) |
| `workspace_snapshots` | `WorkspaceSnapshotRow` (new) | `rowToWorkspaceSnapshot` | `WorkspaceSnapshot` (new, typed; currently `ContextSnapshot` is indirectly embedded) | same |
| `calibration_weights` | `CalibrationWeightRow` (new) | `rowToCalibrationWeight` | `CalibrationWeight` (new) | `src/confidence-calibration.ts` |
| `intel_documents` | `IntelDocumentRow` (exists; `intel/store.ts:162-169`) | `rowToDocument` (rename `rowToIntelDocument`) | `IntelDocument` | `src/intel/store.ts` |
| `schema_version` | `SchemaVersionRow` (new — internal only) | n/a | n/a | `src/migrations/runner.ts` |

### 3.2 Disappearing interfaces

- **`FindingRow`** in `src/types.ts:857-899` → deleted. Replaced by new
  `FindingRow` in `src/store/findings.ts` using snake_case fields.
- **`FindingRowSchema`** in `src/schemas.ts:805-848` → deleted
  (not consumed at runtime).
- **`StoredFindingRecord`** in `src/store.ts:58-108` → renamed
  `StoredFinding` and moved to `src/store/findings.ts` (or wherever A5
  lands). All consumers (`report-*.ts`, CLI review mode, monorepo
  reports) import from new location.
- **`TrajectoryRecord`** in `src/trajectory-memory.ts:19-33` → split into
  `TrajectoryRow` (snake_case, SQL-shape) and `Trajectory` (camelCase).
- **`PipelineRunRecord`** in `src/store.ts:41-56` → renamed
  `PipelineRun`; `PipelineRunRow` is the snake_case SQL-shape sibling.

### 3.3 No interface should own "mixed" naming

Today `FindingRow` mixes camelCase field names with `*Json` suffixes
that describe the *type* of the value (1.6, 1.15). The new rule:

- **Row types** use snake_case mirroring the column names verbatim.
  `verification_steps_json`, `verify_preconditions_json`, etc.
- **Domain types** use camelCase and the parsed form (`verificationSteps:
  string[]`, `verifyPreconditions: string[]`). No `*Json` field on a
  domain type — if it's JSON, it's parsed by the mapper.

---

## 4. Column / field naming rulebook

Proposed rules. Each rule is followed by a table of violators today.

### Rule N-1: Timestamps end `_at`, ISO-8601 TEXT stored at second precision.

Current state: 100% compliant on TS side (`*At`) and ~95% on SQL side.
No violators. Keep.

### Rule N-2: Durations end `_ms` (milliseconds) or `_ns` (nanoseconds) depending on unit stored. Document unit in comment.

Current state: compliant. No violators. Rule written down for
posterity.

### Rule N-3: Monetary amounts end `_cost_usd` (for per-row cost) or `_budget_usd` (for budgets / limits). Numeric REAL.

| Column | Violates how | Proposed rename |
|---|---|---|
| *(none found today)* | | |

TS side: every `*CostUsd` / `*BudgetUsd` consistent.

### Rule N-4: JSON-blob columns end `_json`. Column value is a JSON-serialized string; NULL allowed unless explicitly NOT NULL.

| Column | Currently | Proposed |
|---|---|---|
| `findings.verification_steps` | JSON array, no suffix | `findings.verification_steps_json` |
| `findings.verify_preconditions` | JSON array, no suffix | `findings.verify_preconditions_json` |
| `code_graph_paths.path_node_ids` | JSON array | `code_graph_paths.path_node_ids_json` |
| `code_graph_paths.path_edge_ids` | JSON array | `code_graph_paths.path_edge_ids_json` |
| `code_graph_paths.sanitizer_nodes` | JSON array | `code_graph_paths.sanitizer_node_ids_json` |

### Rule N-5: Booleans stored as INTEGER get a `_flag` suffix and a CHECK (column IN (0,1)). NULL allowed for "not yet evaluated".

| Column | Currently | Proposed |
|---|---|---|
| `findings.verify_exploitable` | INTEGER 0/1 | `findings.verify_exploitable_flag` |
| `findings.poc_harness_parsed` | INTEGER 0/1 | `findings.poc_harness_parsed_flag` |
| `findings.poc_harness_skipped` | INTEGER 0/1 | `findings.poc_harness_skipped_flag` |
| `trajectories.was_correct` | INTEGER 0/1/NULL | `trajectories.was_correct_flag` |
| `finding_assertions.passed` | INTEGER 0/1 | `finding_assertions.passed_flag` |
| `code_graph_paths.has_sanitizer` | INTEGER 0/1 | `code_graph_paths.has_sanitizer_flag` |

CHECK constraint delegation: A4's job.

### Rule N-6: PK column is always `<entity_singular>_id TEXT PRIMARY KEY` (UUIDs, deterministic hashes, natural keys). Auto-increment integer PKs only where the row genuinely has no external identity.

| Table | Currently | Proposed |
|---|---|---|
| `trajectories.id` | generic `id` | `trajectories.trajectory_id` |
| `finding_assertions.id` | AUTOINCREMENT INTEGER | keep as-is (no external identity), but rename → `assertion_id` |
| `workspaces.id` | generic `id` | `workspaces.workspace_id` |
| `workspace_snapshots.id` | AUTOINCREMENT INTEGER | keep, rename → `snapshot_id` |
| `intel_documents.id` | generic `id` | `intel_documents.document_id` |
| `crypto_behavioral_runs.run_id` | collides with `pipeline_runs.run_id` | `crypto_behavioral_runs.crypto_run_id` |

TS-side: `Workspace.id` → `Workspace.workspaceId`;
`Trajectory.id` → `Trajectory.trajectoryId`;
`CryptoBehavioralRun.runId` → `CryptoBehavioralRun.cryptoRunId`;
`IntelDocument.id` → `IntelDocument.documentId`.

### Rule N-7: FK column is always `<referenced_table_singular>_id`.

Current state: compliant.
(`workspace_id`, `pipeline_run_id`, `from_node_id`, `to_node_id`,
`entry_node_id`, `target_node_id`.)

No violators. Keep.

### Rule N-8: Execution-result columns use the prefix `exec_*`, not `execution_*` or `poc_run_*`.

| Column | Currently | Proposed |
|---|---|---|
| `dynamic_analysis_runs.execution_exit_code` | `execution_*` | `dynamic_analysis_runs.exec_exit_code` |
| `dynamic_analysis_runs.execution_stdout` | | `dynamic_analysis_runs.exec_stdout` |
| `dynamic_analysis_runs.execution_stderr` | | `dynamic_analysis_runs.exec_stderr` |
| `dynamic_analysis_runs.execution_verdict` | | `dynamic_analysis_runs.exec_verdict` |
| `dynamic_analysis_runs.execution_duration_ms` | | `dynamic_analysis_runs.exec_duration_ms` |
| `crypto_behavioral_runs.execution_exit_code` | | `crypto_behavioral_runs.exec_exit_code` |
| `crypto_behavioral_runs.execution_verdict` | | `crypto_behavioral_runs.exec_verdict` |
| `crypto_behavioral_runs.execution_stdout` | | `crypto_behavioral_runs.exec_stdout` |
| `crypto_behavioral_runs.execution_stderr` | | `crypto_behavioral_runs.exec_stderr` |
| `crypto_behavioral_runs.execution_duration_ms` | | `crypto_behavioral_runs.exec_duration_ms` |
| `findings.poc_run_exit_code` | `poc_run_*` | `findings.poc_exec_exit_code` |
| `findings.poc_run_stdout` | | `findings.poc_exec_stdout` |
| `findings.poc_run_stderr` | | `findings.poc_exec_stderr` |
| `findings.poc_run_verdict` | | `findings.poc_exec_verdict` |
| `findings.poc_run_duration_ms` | | `findings.poc_exec_duration_ms` |

TS-side: `DynamicAnalysisRun.executionExitCode` → `execExitCode`, etc. (`types.ts:257-261`).
`CryptoBehavioralRun.executionExitCode` → `execExitCode`, etc. (`crypto-behavioral/types.ts:68-72`).
`PocHarnessResult.pocExecExitCode` → **already correct**, no rename.
`FindingRow.pocRunExitCode` / `StoredFindingRecord.pocRunExitCode` → `pocExecExitCode`.

### Rule N-9: Verdict-style enum columns are named `verdict`; lifecycle-style enum columns are named `status`. Pick one semantic per column.

| Table | Current column | Semantic | Proposed |
|---|---|---|---|
| `findings` | `verdict` | verdict | keep |
| `pipeline_runs` | `status` | lifecycle | keep |
| `dynamic_analysis_runs` | `status` | verdict (values: confirmed/interesting/rejected/error) | **rename → `verdict`** |
| `patch_results` | `status` | verdict (values: APPLY_FAILED/.../SOUND/VERIFIED) | **rename → `verdict`** |
| `crypto_behavioral_runs` | `verdict` | verdict | keep |
| `crypto_behavioral_runs` | `execution_verdict` | execution verdict | → `exec_verdict` (see N-8) |

TS side: `DynamicAnalysisRun.status` → `verdict`
(`types.ts:248, 255` and schema at `schemas.ts:264, 276`).
`PatchResult.status` → `verdict` (`types.ts:283, 293` and schema at
`schemas.ts:342-345`). This cascades to the `PatchStatus` /
`DynamicAnalysisStatus` type-alias names (§4.5).

### Rule N-10: Enum type names follow `<Concept>Verdict` or `<Concept>Status`. Status is for lifecycle states.

| TS type | Currently | Proposed |
|---|---|---|
| `PatchStatus` (`types.ts:269-276`) | named `Status` but values are verdicts | `PatchVerdict` |
| `DynamicAnalysisStatus` (`types.ts:239`) | same | `DynamicAnalysisVerdict` |
| `PipelineRunStatus` (`store.ts:32-39`) | genuine lifecycle | keep `PipelineRunStatus` |
| `CryptoBehavioralExecutionVerdict` (`crypto-behavioral/types.ts:11`) | already `*Verdict` | keep |
| `CryptoBehavioralVerdict` (`crypto-behavioral/types.ts:9`) | already | keep |
| `ProofVerdict` (`types.ts:185`) | already | keep |
| `Verdict` (`types.ts:87`) | single-word generic | **rename → `TriageVerdict`** for symmetry and clarity (currently collides in name with `ProofVerdict` etc. in readers' minds) |

### Rule N-11: Prefer explicit table-scoped prefixes over generic column names when the name would be ambiguous in a JOIN.

| Column | Currently | Proposed |
|---|---|---|
| `findings.ref` | ambiguous | `findings.scan_ref` |

### Rule N-12: TS domain type name is singular, no `*Record` or `*Result` suffix unless the thing is itself *the result of an operation*. Row types get `*Row`.

| TS type | Currently | Proposed |
|---|---|---|
| `StoredFindingRecord` (`store.ts:58`) | `*Record` | `StoredFinding` |
| `TrajectoryRecord` (`trajectory-memory.ts:19`) | `*Record` | `Trajectory` (+ add `TrajectoryRow`) |
| `PipelineRunRecord` (`store.ts:41`) | `*Record` | `PipelineRun` (+ add `PipelineRunRow`) |
| `FindingRow` (`types.ts:857`) | existing `*Row` but wrong shape | replace per §3 |
| `WorkspaceRow` (`workspace/manager.ts:103`) | already correct | keep |
| `PatchResultRow` (`store/patch-results.ts:5`) | correct | keep |
| `DynamicAnalysisRunRow` (`store/dynamic-analysis.ts:5`) | correct | keep |
| `CryptoBehavioralRunRow` (`store/crypto-behavioral.ts:5`) | correct | keep |
| `IntelDocumentRow` (`intel/store.ts:162`) | correct | keep |

### Rule N-13: Drop legacy type aliases. One name per concept.

| Alias | Defined | Proposed |
|---|---|---|
| `ScannerId` (`scanners/types.ts:5`) | `= TaskId` | **delete**; everyone uses `TaskId` |
| `ScannerConfig` (`scanners/types.ts:6`) | `= TaskConfig` | **delete** |
| `ModelEvidenceAnchor` (`types.ts:354`) | `= EvidenceAnchor` | already documented back-compat; keep for one release cycle, flag to delete in v101 |

Event-payload followup: `ScanFindingEvent.scannerId`
(`bus/events.ts:186`) → `taskId`. Call sites at
`bus/workers/scan-worker.ts:108` update.

### Rule N-14: Field on a domain type that mirrors an FK must use `<referent>Id`, not abbreviated.

Current state: compliant. `pipelineRunId`, `fingerprint`,
`workspaceId` (in `saveSnapshot` param, `manager.ts:82`) all correct.

### Rule N-15: CSV/enum-string TEXT columns that aren't JSON use exact-match CHECK constraints. (Hands-off to A4.)

No naming violator. Listed so A4 knows what Rule N-5 and the verdict/status
renames imply.

### Rule N-16: Reserved stage names for `taskConfig` blocks (`triage`, `verify`, `poc-harness`) — not columns, but config. Listed for completeness.

Already compliant per `CLAUDE.md` convention.

---

## 5. Cross-cutting observations (flagged, not resolved)

**These belong to A5 (structural), A4 (constraints), or A2 (liveness).
Agent 1 does NOT resolve them.**

### 5.1 (→ A5) `adjusted_score` is a denormalization

`findings.adjusted_score` is `coalesce(score, adjusted_score)` in effect —
`upsertFindingParams` writes `finding.adjustedScore ?? finding.score`
(`store.ts:195`). Readers (`fp-filter.ts:186`, `merge.ts:57`,
`scan-worker.ts:247`, `orchestrator.ts:3243`) always treat missing
`adjusted_score` as `score`. This is a dup-store problem, not a naming
problem. A5 decides: drop the column, or keep for historical reasons.

### 5.2 (→ A5) The 12 JSON blobs on `findings` belong partially in relational tables

From 1.15, `findings` has 8 `*_json` columns (not counting
`pipeline_runs`). Some are genuinely variable-shape
(`triage_details_json`, `finding_metadata_json`); some are pure arrays
of strings (`taint_path_json`, `corroboration_json`,
`suppression_json`, `engine_provenance_json`, `confidence_signals_json`,
`evidence_chain_json`). The array-of-struct ones would be better as
child tables. A5's call.

If A5 keeps them all as JSON: Rule N-4 applies, all suffixes already
correct (or renamed per 1.15). Nothing more for A1.

### 5.3 (→ A2) Dead-or-near-dead columns

Flagged for A2's dead-code sweep — from A1's vantage these need
naming decisions *iff* A2 decides to keep them:

- `findings.calibrated_confidence` — written by
  `confidence-calibration.ts:238`, never read back by any mapper I
  traced. Agent 2 should confirm.
- `findings.evidence_chain_json` — same; only written, never SELECTed.
- `findings.composite_confidence` — written (`store.ts:229`), not
  read back by any mapper in `getActionableFindings`
  (not in the SELECT at `store.ts:783-813`).
- `findings.confidence_signals_json` — same; the `_updateFindingCompositeConfidence`
  function (`store.ts:1403-1414`) is marked underscore-private
  (dead-code marker) and grep shows no callers.
- `pipeline_runs.prompt_hash`, `pipeline_runs.assertions_json` —
  written by `_updatePromptHash` / `_updateRunAssertions`
  (`store.ts:1792-1803`), both underscore-private.
- `pipeline_runs.metrics_json` — written by `updateRunMetrics`
  (`store.ts:1417-1423`), readers exist in `monorepo` reporting.
- `workspaces.updated_at` — written, never SELECT'd by name
  (1.21).

### 5.4 (→ A4) CHECK constraint must expand verdict enum

`001_initial_schema.ts:22` CHECK excludes `'by_design'`. A4's job. Doing
the v100 reset drops the old constraint anyway.

Enum columns per Rule N-9 rename (→ `verdict`) need new CHECKs:
- `dynamic_analysis_runs.verdict`: `IN ('confirmed','interesting','rejected','error')`.
- `patch_results.verdict`: `IN ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE','TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')`.
- `crypto_behavioral_runs.verdict`: `IN ('vulnerable','secure','inconclusive','error')`.
- `crypto_behavioral_runs.exec_verdict`: `IN ('PASS','FAIL','ERROR','TIMEOUT')`.
- `findings.poc_exec_verdict`: same as above.
- `dynamic_analysis_runs.exec_verdict`: same as above.

### 5.5 (→ A4) UNIQUE on `(repo, scan_ref, fingerprint)`

Plan already calls this out. Agent 1 flags that after the
`ref → scan_ref` rename (1.13, Rule N-11), the composite becomes
`(repo, scan_ref, fingerprint)`.

### 5.6 (→ A5) `pipeline_runs.findings_json` is a snapshot duplicate

`pipeline_runs.findings_json` stores a JSON dump of the `findings` rows
at scan-complete time (`store.ts:1139-1145`). Denormalization —
A5's call. Naming-wise `findings_json` is compliant.

### 5.7 (→ A5) Split update paths

`updateVerificationResult` (`store.ts:1426-1453`) +
`updateVerificationCost` (`store.ts:1456-1472`) both touch
`findings`. `updatePocHarnessResult` (`store.ts:1474-1512`) +
`updatePocHarnessCost` (`store.ts:1515-1531`) same. Structural.

### 5.8 (→ A3) `intel_documents` / `intel_fts` created ad-hoc

`intel/store.ts:20-57` creates the FTS5 schema outside the migration
system. Migration 3's territory.

### 5.9 (→ A3) `trajectories` has both migration 011 `CREATE TABLE` and runtime `ensureTrajectoryTable`

`trajectory-memory.ts:121-141` re-creates the same table at runtime.
Idempotent, but two sources of truth. A3's call.

---

## 6. Draft SQL — v100 fresh schema (naming only)

**Scope of this SQL:**
- Applies every rename from §4.
- Does **NOT** specify CHECK / NOT NULL / UNIQUE / FK (A4 territory).
  Existing CHECKs are dropped; A4 re-adds per 5.4.
- Does **NOT** split/merge tables (A5 territory). Markers `-- A5:`
  flag places A5 may want to restructure.
- Drops columns flagged dead by A1's reading (marked `-- A2:`);
  A2's final list supersedes.
- Uses `-- A3:` markers where A3's reset mechanism needs to know
  something.

```sql
---------------------------------------------------------------
-- findings (core table)
-- A3: consolidated from migrations 001, 002, 003, 004, 005,
--     006, 007, 010, 012, 013, 016, 017, 021, 022, 024.
-- A5: 8 *_json columns may become child tables; see 5.2.
---------------------------------------------------------------
CREATE TABLE findings (
  fingerprint                     TEXT PRIMARY KEY,
  task_id                         TEXT,              -- renamed from `scanner` (migration 024)
  repo                            TEXT,
  scan_ref                        TEXT,              -- renamed from `ref`  (Rule N-11)
  rule_id                         TEXT,
  file_path                       TEXT,
  start_line                      INTEGER,
  severity                        TEXT,
  message                         TEXT,

  -- triage
  verdict                         TEXT,              -- A4: CHECK incl. 'by_design'
  confidence                      REAL,              -- A4: CHECK 0..1
  rationale                       TEXT,
  verification_steps_json         TEXT,              -- renamed from verification_steps  (Rule N-4)
  fix_patch                       TEXT,
  triage_cost_usd                 REAL,              -- A5: may move to finding_costs child table
  triage_details_json             TEXT,              -- A5: candidate for extraction
  composite_confidence            REAL,              -- A2: check liveness
  confidence_signals_json         TEXT,              -- A2: check liveness
  calibrated_confidence           REAL,              -- A2: check liveness
  evidence_chain_json             TEXT,              -- A2: check liveness

  -- verification
  verify_exploitable_flag         INTEGER,           -- renamed from verify_exploitable  (Rule N-5); A4: CHECK IN (0,1)
  verify_poc_payload              TEXT,
  verify_poc_description          TEXT,
  verify_attack_vector            TEXT,
  verify_preconditions_json       TEXT,              -- renamed from verify_preconditions  (Rule N-4)
  verify_confidence               REAL,              -- A4: CHECK 0..1
  verify_cost_usd                 REAL,              -- A5: candidate for finding_costs

  -- poc harness (generation)
  poc_harness_path                TEXT,
  poc_harness_language            TEXT,
  poc_harness_parsed_flag         INTEGER,           -- renamed (Rule N-5); A4: CHECK IN (0,1)
  poc_harness_parse_error         TEXT,
  poc_harness_skipped_flag        INTEGER,           -- renamed (Rule N-5); A4: CHECK IN (0,1)
  poc_harness_skip_reason         TEXT,
  poc_harness_cost_usd            REAL,              -- A5: candidate for finding_costs

  -- poc exec (execution)
  poc_exec_exit_code              INTEGER,           -- renamed from poc_run_exit_code    (Rule N-8)
  poc_exec_stdout                 TEXT,              -- renamed from poc_run_stdout       (Rule N-8)
  poc_exec_stderr                 TEXT,              -- renamed from poc_run_stderr       (Rule N-8)
  poc_exec_verdict                TEXT,              -- renamed from poc_run_verdict      (Rule N-8); A4: CHECK IN PASS|FAIL|ERROR|TIMEOUT
  poc_exec_duration_ms            REAL,              -- renamed from poc_run_duration_ms  (Rule N-8)

  -- scan-layer provenance
  adjusted_score                  REAL,              -- A5: denormalization of score
  corroboration_json              TEXT,              -- A5: candidate for extraction
  suppression_json                TEXT,              -- A5: candidate for extraction
  taint_path_json                 TEXT,              -- A5: candidate for extraction
  proof_state                     TEXT,              -- A4: CHECK
  engine_provenance_json          TEXT,              -- A5: candidate for extraction
  finding_metadata_json           TEXT,              -- A5: extract blame.*/introducedIn

  created_at                      TEXT,
  updated_at                      TEXT
);
-- A4: UNIQUE (repo, scan_ref, fingerprint); FK implied by natural key only.

CREATE INDEX idx_findings_repo_ref   ON findings(repo, scan_ref);
CREATE INDEX idx_findings_rule_id    ON findings(rule_id);
CREATE INDEX idx_findings_task_id    ON findings(task_id);
CREATE INDEX idx_findings_file_path  ON findings(file_path);
CREATE INDEX idx_findings_verdict    ON findings(verdict);

---------------------------------------------------------------
-- pipeline_runs
-- A3: consolidated from 001, 008, 009, 014, 015, 021, 023.
-- A5: findings_json is a snapshot dup of findings rows; keep or drop.
---------------------------------------------------------------
CREATE TABLE pipeline_runs (
  run_id           TEXT PRIMARY KEY,
  repo             TEXT,
  started_at       TEXT,
  status           TEXT,                   -- A4: CHECK (lifecycle)
  config_json      TEXT,
  scan_opts_json   TEXT,
  findings_json    TEXT,                   -- A5: snapshot — decide keep/drop
  context_json     TEXT,
  total_cost_usd   REAL,
  completed_at     TEXT,
  metrics_json     TEXT,
  assertions_json  TEXT,                   -- A2: check liveness
  prompt_hash      TEXT,                   -- A2: check liveness
  head_ref         TEXT,
  updated_at       TEXT
);

CREATE INDEX idx_pipeline_runs_repo_status ON pipeline_runs(repo, status);
CREATE INDEX idx_pipeline_runs_started_at  ON pipeline_runs(started_at DESC);

---------------------------------------------------------------
-- trajectories
-- A3: from migration 011. Drop runtime ensureTrajectoryTable().
---------------------------------------------------------------
CREATE TABLE trajectories (
  trajectory_id    TEXT PRIMARY KEY,       -- renamed from `id`           (Rule N-6)
  rule_id          TEXT,
  cwes_json        TEXT,
  task_id          TEXT,
  verdict          TEXT,                   -- A4: CHECK (TriageVerdict)
  confidence       REAL,
  was_correct_flag INTEGER,                -- renamed from was_correct   (Rule N-5); A4: CHECK IN (0,1)
  steps_json       TEXT,
  summary          TEXT,
  repo             TEXT,
  fingerprint      TEXT,                   -- A4: FK -> findings.fingerprint
  created_at       TEXT,
  updated_at       TEXT
);

CREATE INDEX idx_trajectories_rule_id     ON trajectories(rule_id);
CREATE INDEX idx_trajectories_was_correct ON trajectories(was_correct_flag);

---------------------------------------------------------------
-- finding_assertions
-- A3: from migration 015. A2: flag for liveness (reader is _underscored).
---------------------------------------------------------------
CREATE TABLE finding_assertions (
  assertion_id    INTEGER PRIMARY KEY AUTOINCREMENT,  -- renamed from `id` (Rule N-6)
  run_id          TEXT,                               -- A4: FK -> pipeline_runs.run_id
  fingerprint     TEXT,                               -- A4: FK -> findings.fingerprint
  assertion_name  TEXT,
  passed_flag     INTEGER,                            -- renamed from passed (Rule N-5); A4: CHECK IN (0,1)
  score           REAL,
  weight          REAL,
  reason          TEXT,
  created_at      TEXT
);

CREATE INDEX idx_finding_assertions_run ON finding_assertions(run_id);

---------------------------------------------------------------
-- dynamic_analysis_runs
-- A3: from migrations 017, 020 (020 only touches patch_results).
---------------------------------------------------------------
CREATE TABLE dynamic_analysis_runs (
  dynamic_run_id     TEXT PRIMARY KEY,
  pipeline_run_id    TEXT,                 -- A4: FK -> pipeline_runs.run_id
  fingerprint        TEXT,                 -- A4: FK -> findings.fingerprint
  repo               TEXT,
  verdict            TEXT,                 -- renamed from `status` (Rule N-9); A4: CHECK IN (confirmed|interesting|rejected|error)
  score              REAL,
  proof_value        REAL,
  language           TEXT,
  harness_path       TEXT,
  harness_language   TEXT,
  seed_inputs_json   TEXT,
  coverage_mode      TEXT,                 -- A4: CHECK IN (none|node-v8|python-coverage)
  coverage_summary   TEXT,
  exec_exit_code     INTEGER,              -- renamed from execution_exit_code   (Rule N-8)
  exec_stdout        TEXT,                 -- renamed from execution_stdout      (Rule N-8)
  exec_stderr        TEXT,                 -- renamed from execution_stderr      (Rule N-8)
  exec_verdict       TEXT,                 -- renamed from execution_verdict     (Rule N-8); A4: CHECK IN (PASS|FAIL|ERROR|TIMEOUT)
  exec_duration_ms   INTEGER,              -- renamed from execution_duration_ms (Rule N-8)
  iterations         INTEGER,
  cost_usd           REAL,                 -- A5: candidate for finding_costs (if A5 extracts)
  metadata_json      TEXT,
  created_at         TEXT,
  updated_at         TEXT
);

CREATE INDEX idx_dynamic_analysis_runs_fingerprint ON dynamic_analysis_runs(fingerprint, created_at DESC);
CREATE INDEX idx_dynamic_analysis_runs_repo_status ON dynamic_analysis_runs(repo, verdict);

---------------------------------------------------------------
-- patch_results
-- A3: from migrations 017 + 020 (extended status enum).
---------------------------------------------------------------
CREATE TABLE patch_results (
  patch_run_id    TEXT PRIMARY KEY,
  fingerprint     TEXT,                    -- A4: FK -> findings.fingerprint
  repo            TEXT,
  diff            TEXT,
  verdict         TEXT,                    -- renamed from `status` (Rule N-9); A4: CHECK IN (APPLY_FAILED|BUILD_FAILED|STILL_VULNERABLE|TESTS_FAILED|SOUND|VERIFIED|UNKNOWN)
  iterations      INTEGER,
  build_command   TEXT,
  test_command    TEXT,
  worktree_path   TEXT,
  cost_usd        REAL,                    -- A5: candidate for finding_costs
  validator_log   TEXT,
  history_json    TEXT,
  created_at      TEXT,
  updated_at      TEXT
);

CREATE INDEX idx_patch_results_fingerprint   ON patch_results(fingerprint, created_at DESC);
CREATE INDEX idx_patch_results_repo_status   ON patch_results(repo, verdict);

---------------------------------------------------------------
-- crypto_behavioral_runs
-- A3: from migration 018. Column `run_id` renamed to disambiguate from pipeline_runs.run_id.
---------------------------------------------------------------
CREATE TABLE crypto_behavioral_runs (
  crypto_run_id      TEXT PRIMARY KEY,     -- renamed from `run_id` (Rule N-6 + 1.17)
  pipeline_run_id    TEXT,                 -- A4: FK -> pipeline_runs.run_id
  fingerprint        TEXT,                 -- A4: FK -> findings.fingerprint
  repo               TEXT,
  test_type          TEXT,                 -- A4: CHECK IN (timing|ecb-mode|weak-hash|weak-prng|key-length|edge-case)
  verdict            TEXT,                 -- A4: CHECK IN (vulnerable|secure|inconclusive|error)
  harness_path       TEXT,
  harness_language   TEXT,
  exec_exit_code     INTEGER,              -- renamed from execution_exit_code   (Rule N-8)
  exec_verdict       TEXT,                 -- renamed from execution_verdict     (Rule N-8); A4: CHECK IN (PASS|FAIL|ERROR|TIMEOUT)
  exec_stdout        TEXT,                 -- renamed from execution_stdout      (Rule N-8)
  exec_stderr        TEXT,                 -- renamed from execution_stderr      (Rule N-8)
  exec_duration_ms   INTEGER,              -- renamed from execution_duration_ms (Rule N-8)
  t_statistic        REAL,
  p_value            REAL,
  mean_a_ns          REAL,
  mean_b_ns          REAL,
  timing_iterations  INTEGER,
  observed_behavior  TEXT,
  expected_behavior  TEXT,
  algorithm_confirmed TEXT,
  key_length_bits    INTEGER,
  cost_usd           REAL,
  metadata_json      TEXT,
  created_at         TEXT,
  updated_at         TEXT
);

CREATE INDEX idx_crypto_behavioral_fingerprint ON crypto_behavioral_runs(fingerprint, created_at DESC);

---------------------------------------------------------------
-- code_graph_nodes
-- A3: from migration 019.
---------------------------------------------------------------
CREATE TABLE code_graph_nodes (
  node_id         TEXT PRIMARY KEY,
  repo            TEXT,
  run_id          TEXT,                    -- A4: FK -> pipeline_runs.run_id
  file_path       TEXT,
  start_line      INTEGER,
  symbol          TEXT,
  node_kind       TEXT,                    -- A4: CHECK IN (entry-http|entry-cli|...|unknown)
  framework       TEXT,
  metadata_json   TEXT,
  confidence      REAL,
  source          TEXT,                    -- A4: CHECK IN (static|llm|hybrid)
  created_at      TEXT,
  updated_at      TEXT
);

CREATE INDEX idx_cgn_repo  ON code_graph_nodes(repo);
CREATE INDEX idx_cgn_file  ON code_graph_nodes(repo, file_path);
CREATE INDEX idx_cgn_kind  ON code_graph_nodes(repo, node_kind);

---------------------------------------------------------------
-- code_graph_edges
---------------------------------------------------------------
CREATE TABLE code_graph_edges (
  edge_id       TEXT PRIMARY KEY,
  repo          TEXT,
  run_id        TEXT,                      -- A4: FK -> pipeline_runs.run_id
  from_node_id  TEXT,                      -- A4: FK -> code_graph_nodes.node_id
  to_node_id    TEXT,                      -- A4: FK -> code_graph_nodes.node_id
  edge_kind     TEXT,                      -- A4: CHECK IN (calls|imports|...|serialization)
  data_label    TEXT,
  ordinal       INTEGER,
  confidence    REAL,
  source        TEXT,                      -- A4: CHECK IN (static|llm|hybrid)
  created_at    TEXT
);

CREATE INDEX idx_cge_repo ON code_graph_edges(repo);
CREATE INDEX idx_cge_from ON code_graph_edges(from_node_id);
CREATE INDEX idx_cge_to   ON code_graph_edges(to_node_id);

---------------------------------------------------------------
-- code_graph_paths
---------------------------------------------------------------
CREATE TABLE code_graph_paths (
  path_id                   TEXT PRIMARY KEY,
  repo                      TEXT,
  run_id                    TEXT,          -- A4: FK -> pipeline_runs.run_id
  entry_node_id             TEXT,          -- A4: FK -> code_graph_nodes.node_id
  target_node_id            TEXT,          -- A4: FK -> code_graph_nodes.node_id
  hop_count                 INTEGER,
  path_node_ids_json        TEXT,          -- renamed from path_node_ids    (Rule N-4)
  path_edge_ids_json        TEXT,          -- renamed from path_edge_ids    (Rule N-4)
  has_sanitizer_flag        INTEGER,       -- renamed (Rule N-5); A4: CHECK IN (0,1)
  sanitizer_node_ids_json   TEXT,          -- renamed from sanitizer_nodes  (Rule N-4 + 1.18)
  confidence                REAL,
  created_at                TEXT
);

CREATE INDEX idx_cgp_target ON code_graph_paths(repo, target_node_id);
CREATE INDEX idx_cgp_entry  ON code_graph_paths(repo, entry_node_id);

---------------------------------------------------------------
-- workspaces
-- A3: from migration 025. A1: add updated_at to TS Workspace.
---------------------------------------------------------------
CREATE TABLE workspaces (
  workspace_id     TEXT PRIMARY KEY,       -- renamed from `id`      (Rule N-6)
  name             TEXT,                   -- A4: UNIQUE
  targets_json     TEXT,
  metadata_json    TEXT,
  created_at       TEXT,
  last_accessed_at TEXT,
  updated_at       TEXT
);

---------------------------------------------------------------
-- workspace_snapshots
---------------------------------------------------------------
CREATE TABLE workspace_snapshots (
  snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,  -- renamed from `id` (Rule N-6)
  workspace_id   TEXT,                                -- A4: FK -> workspaces.workspace_id ON DELETE CASCADE
  snapshot_json  TEXT,
  created_at     TEXT
);

CREATE INDEX idx_workspace_snapshots_workspace ON workspace_snapshots(workspace_id);

---------------------------------------------------------------
-- calibration_weights
-- A3: from migration 010. Composite PK preserved.
---------------------------------------------------------------
CREATE TABLE calibration_weights (
  step_type     TEXT,
  rule_family   TEXT,
  weight        REAL,
  sample_count  INTEGER,
  updated_at    TEXT,
  PRIMARY KEY (step_type, rule_family)
);

---------------------------------------------------------------
-- intel_documents
-- A3: promote from ad-hoc createIntelTables() to v100.
---------------------------------------------------------------
CREATE TABLE intel_documents (
  document_id    TEXT PRIMARY KEY,          -- renamed from `id` (Rule N-6)
  source         TEXT,
  title          TEXT,
  content        TEXT,
  metadata_json  TEXT,
  ingested_at    TEXT
);

CREATE INDEX idx_intel_source ON intel_documents(source);

CREATE VIRTUAL TABLE intel_fts USING fts5(
  title,
  content,
  content='intel_documents',
  content_rowid='rowid'
);

-- A3: triggers relocate from intel/store.ts
CREATE TRIGGER intel_ai AFTER INSERT ON intel_documents BEGIN
  INSERT INTO intel_fts(rowid, title, content)
    VALUES (new.rowid, new.title, new.content);
END;

CREATE TRIGGER intel_ad AFTER DELETE ON intel_documents BEGIN
  INSERT INTO intel_fts(intel_fts, rowid, title, content)
    VALUES ('delete', old.rowid, old.title, old.content);
END;

CREATE TRIGGER intel_au AFTER UPDATE ON intel_documents BEGIN
  INSERT INTO intel_fts(intel_fts, rowid, title, content)
    VALUES ('delete', old.rowid, old.title, old.content);
  INSERT INTO intel_fts(rowid, title, content)
    VALUES (new.rowid, new.title, new.content);
END;

---------------------------------------------------------------
-- schema_version (bookkeeping — A3's territory)
---------------------------------------------------------------
-- Managed entirely by src/migrations/runner.ts; no rename proposed.
```

---

## 7. Flat rename table (the "one-page diff")

Every proposed rename in the entire document, consolidated. Use this
as the Phase B conflict-resolution checklist.

### 7.1 Column renames

| Old column | New column | Rule | Ref |
|---|---|---|---|
| `findings.ref` | `findings.scan_ref` | N-11 | 1.13 |
| `findings.verification_steps` | `findings.verification_steps_json` | N-4 | 1.6, 1.15 |
| `findings.verify_preconditions` | `findings.verify_preconditions_json` | N-4 | 1.15 |
| `findings.verify_exploitable` | `findings.verify_exploitable_flag` | N-5 | 1.12 |
| `findings.poc_harness_parsed` | `findings.poc_harness_parsed_flag` | N-5 | 1.12 |
| `findings.poc_harness_skipped` | `findings.poc_harness_skipped_flag` | N-5 | 1.12 |
| `findings.poc_run_exit_code` | `findings.poc_exec_exit_code` | N-8 | 1.11, 1.19 |
| `findings.poc_run_stdout` | `findings.poc_exec_stdout` | N-8 | 1.11, 1.19 |
| `findings.poc_run_stderr` | `findings.poc_exec_stderr` | N-8 | 1.11, 1.19 |
| `findings.poc_run_verdict` | `findings.poc_exec_verdict` | N-8 | 1.11, 1.19 |
| `findings.poc_run_duration_ms` | `findings.poc_exec_duration_ms` | N-8 | 1.11, 1.19 |
| `dynamic_analysis_runs.status` | `dynamic_analysis_runs.verdict` | N-9 | 1.4 |
| `dynamic_analysis_runs.execution_exit_code` | `dynamic_analysis_runs.exec_exit_code` | N-8 | 1.19 |
| `dynamic_analysis_runs.execution_stdout` | `dynamic_analysis_runs.exec_stdout` | N-8 | 1.19 |
| `dynamic_analysis_runs.execution_stderr` | `dynamic_analysis_runs.exec_stderr` | N-8 | 1.19 |
| `dynamic_analysis_runs.execution_verdict` | `dynamic_analysis_runs.exec_verdict` | N-8 | 1.19 |
| `dynamic_analysis_runs.execution_duration_ms` | `dynamic_analysis_runs.exec_duration_ms` | N-8 | 1.19 |
| `patch_results.status` | `patch_results.verdict` | N-9 | 1.4 |
| `crypto_behavioral_runs.run_id` | `crypto_behavioral_runs.crypto_run_id` | N-6 | 1.16, 1.17 |
| `crypto_behavioral_runs.execution_exit_code` | `crypto_behavioral_runs.exec_exit_code` | N-8 | 1.19 |
| `crypto_behavioral_runs.execution_verdict` | `crypto_behavioral_runs.exec_verdict` | N-8 | 1.19 |
| `crypto_behavioral_runs.execution_stdout` | `crypto_behavioral_runs.exec_stdout` | N-8 | 1.19 |
| `crypto_behavioral_runs.execution_stderr` | `crypto_behavioral_runs.exec_stderr` | N-8 | 1.19 |
| `crypto_behavioral_runs.execution_duration_ms` | `crypto_behavioral_runs.exec_duration_ms` | N-8 | 1.19 |
| `trajectories.id` | `trajectories.trajectory_id` | N-6 | 1.16 |
| `trajectories.was_correct` | `trajectories.was_correct_flag` | N-5 | 1.12 |
| `finding_assertions.id` | `finding_assertions.assertion_id` | N-6 | 1.16 |
| `finding_assertions.passed` | `finding_assertions.passed_flag` | N-5 | 1.12 |
| `workspaces.id` | `workspaces.workspace_id` | N-6 | 1.16 |
| `workspace_snapshots.id` | `workspace_snapshots.snapshot_id` | N-6 | 1.16 |
| `intel_documents.id` | `intel_documents.document_id` | N-6 | 1.16 |
| `code_graph_paths.path_node_ids` | `code_graph_paths.path_node_ids_json` | N-4 | 1.15, 1.18 |
| `code_graph_paths.path_edge_ids` | `code_graph_paths.path_edge_ids_json` | N-4 | 1.15, 1.18 |
| `code_graph_paths.sanitizer_nodes` | `code_graph_paths.sanitizer_node_ids_json` | N-4, N-7 | 1.15, 1.18 |
| `code_graph_paths.has_sanitizer` | `code_graph_paths.has_sanitizer_flag` | N-5 | 1.12 |

### 7.2 TypeScript type / field renames

| Old symbol | New symbol | Ref |
|---|---|---|
| `Verdict` (`types.ts:87`) | `TriageVerdict` | N-10, 1.4 |
| `PatchStatus` (`types.ts:269-276`) | `PatchVerdict` | N-10, 1.4 |
| `DynamicAnalysisStatus` (`types.ts:239`) | `DynamicAnalysisVerdict` | N-10, 1.4 |
| `ScannerId` (`scanners/types.ts:5`) | **deleted** — use `TaskId` | N-13, 1.7 |
| `ScannerConfig` (`scanners/types.ts:6`) | **deleted** — use `TaskConfig` | N-13, 1.7 |
| `FindingRow` (`types.ts:857-899`) | **deleted** — replaced per §3 | §2, §3 |
| `FindingRowSchema` (`schemas.ts:805-848`) | **deleted** — not used | §2 |
| `StoredFindingRecord` (`store.ts:58-108`) | `StoredFinding` (+ new `FindingRow`) | N-12, §2 |
| `PipelineRunRecord` (`store.ts:41-56`) | `PipelineRun` (+ new `PipelineRunRow`) | N-12, §3 |
| `TrajectoryRecord` (`trajectory-memory.ts:19-33`) | `Trajectory` (+ new `TrajectoryRow`) | N-12, 1.20 |
| `TriageResult.fixPatch` | keep as-is | — |
| `TriageResult.verificationSteps` | keep as parsed `string[]` on domain; row type gets `verification_steps_json: string` | 1.6 |
| `VerificationResult.exploitable` | keep as `boolean` on domain; row type gets `verify_exploitable_flag: number \| null` | 1.12 |
| `DynamicAnalysisRun.status` | `DynamicAnalysisRun.verdict` | N-9, 1.4 |
| `DynamicAnalysisRun.executionExitCode` | `DynamicAnalysisRun.execExitCode` | N-8 |
| `DynamicAnalysisRun.executionStdout` | `DynamicAnalysisRun.execStdout` | N-8 |
| `DynamicAnalysisRun.executionStderr` | `DynamicAnalysisRun.execStderr` | N-8 |
| `DynamicAnalysisRun.executionVerdict` | `DynamicAnalysisRun.execVerdict` | N-8 |
| `DynamicAnalysisRun.executionDurationMs` | `DynamicAnalysisRun.execDurationMs` | N-8 |
| `PatchResult.status` | `PatchResult.verdict` | N-9 |
| `CryptoBehavioralRun.runId` | `CryptoBehavioralRun.cryptoRunId` | N-6, 1.17 |
| `CryptoBehavioralRun.executionExitCode` | `CryptoBehavioralRun.execExitCode` | N-8 |
| `CryptoBehavioralRun.executionVerdict` | `CryptoBehavioralRun.execVerdict` | N-8 |
| `CryptoBehavioralRun.executionStdout` | `CryptoBehavioralRun.execStdout` | N-8 |
| `CryptoBehavioralRun.executionStderr` | `CryptoBehavioralRun.execStderr` | N-8 |
| `CryptoBehavioralRun.executionDurationMs` | `CryptoBehavioralRun.execDurationMs` | N-8 |
| `Workspace.id` | `Workspace.workspaceId` | N-6 |
| `Workspace` (add `updatedAt: string`) | — | 1.21 |
| `Trajectory.id` (after §3 split) | `Trajectory.trajectoryId` | N-6 |
| `IntelDocument.id` | `IntelDocument.documentId` | N-6 |
| `ScanFindingEvent.scannerId` (`bus/events.ts:186`) | `ScanFindingEvent.taskId` | 1.7, 1.22 |
| `FindingRow.pocRunExitCode` and peers | replaced by new `FindingRow` / `StoredFinding` with `pocExecExitCode` etc. | 1.11 |
| `TriageResult` (add `sinkFunction?: string \| null`) | consistent w/ `schemas.ts:181` | §1 (no mismatch found but worth noting) |
| `PocHarnessResult.pocExec*` | keep unchanged (already correct) | §4 Rule N-8 |

### 7.3 Schema / Zod renames that follow automatically

| File | Current | Proposed |
|---|---|---|
| `schemas.ts:805` `FindingRowSchema` | exists | delete |
| `schemas.ts:264, 276` `DynamicAnalysisRunSchema.status` | `status` | `verdict` |
| `schemas.ts:342-345` `PatchResultSchema.status` | `status` | `verdict` |
| `schemas.ts` `PocHarnessResultSchema.pocExec*` | already `exec`-prefixed | keep |
| `schemas.ts` `VerificationResultSchema.exploitable` | `boolean` | keep |

---

## 8. Verification of this document

Self-check:

- [x] Every rename has a rule N-* reference and a source-of-truth
      `path:line` ref.
- [x] All rename proposals consolidated in §7 for one-page diff
      review.
- [x] Every `*_json` column with a JSON payload listed in §1.15 and
      §4 N-4. Violators: 5 columns.
- [x] Every `INTEGER 0/1` boolean listed: 6 columns.
- [x] A5's territory (structural split/merge): §5.1, §5.2, §5.6, §5.7
      flagged and NOT resolved.
- [x] A4's territory (CHECK/FK/UNIQUE): §5.4, §5.5 flagged and NOT
      resolved. Draft SQL in §6 has no CHECK/FK/UNIQUE/NOT NULL — all
      marked with `-- A4:` comments.
- [x] A2's territory (dead columns): §5.3 lists candidates without
      deciding. Draft SQL in §6 marks `-- A2:` on each candidate.
- [x] A3's territory (mechanics/reset): §6 marks `-- A3:`
      consolidation points.
- [x] The four-way type redundancy (`Finding`, `TriageResult`,
      `FindingRow`, `StoredFindingRecord`) is explicitly collapsed in
      §2 with proposed replacements.
- [x] Cross-agent precedence per `_column-ownership.md`: A5 > A2 > A4 >
      A1 > A3 is honored; A1 flags but does not resolve others.

End of Agent 1 assessment.
