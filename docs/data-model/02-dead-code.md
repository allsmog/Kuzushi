# Agent 2 — Dead Code & Unused Columns

Phase-A research. READ-ONLY on code; this is the only file Agent 2 writes.
Plan: `/home/node/.claude/plans/ok-i-want-to-synchronous-crescent.md`.
Coordination: `docs/data-model/_column-ownership.md`.

## 1. Methodology

- **Definition of "real read":** a `SELECT` (or `RETURNING`) in live code whose projected value is observed downstream — propagated into a type, logged, pushed to an event, or used in a conditional. A `SELECT *` that maps a column into a row-struct counts only if some live caller of that struct reads the field. If the only readers are row-mappers whose outputs are never consumed, the column is flagged write-only.
- **"Live code":** anything under `src/` that a public export, a `bus.subscribe` handler, a CLI entry point, or an orchestrator stage transitively reaches. Functions prefixed with `_` (convention for "kept around, known unused") are treated as dead.
- **"Test-only":** references under `tests/`, `tests/e2e/`, or any file matching `*.test.ts`. These do not count as real reads in the census. They are called out when they are the *only* reference so the test-cleanup in Phase C Commit 3 can delete them.
- **Search patterns used:** for each column I grepped:
  - SQL-side snake_case (literal column name)
  - TS-side camelCase (TS field name)
  - SQL-side `<col> as <alias>` patterns to find projections
  - Both write sites (`INSERT`, `UPDATE`, `ADD COLUMN`, upsert params) and read sites (`SELECT`, field accesses on struct)
- **Tooling:** `Grep` with snake_case and camelCase patterns across `src/` and `tests/`; `Read` for source, migrations, and store modules.
- **What I excluded from real-read counts:**
  - `generated/db/schema.sql` (a derived artifact, not code).
  - Migration files (appear in `src/migrations/*.ts` but are schema-creation only, not runtime reads/writes of user data).
  - Bash e2e scripts under `tests/e2e/` that query the DB only to verify the column exists.
  - Functions prefixed with `_` in `src/store.ts` (`_updateFindingCompositeConfidence`, `_updateRunAssertions`, `_updatePromptHash`, `_getRunAssertions`, `_getTotalVerificationCost`, `_getVerificationCounts`, `_parsePatchStatus`). These are kept for future use; callers do not exist.

Evidence format below: `src/file.ts:line` with a short note. Counts are approximate — I only listed the top 2–3 refs per column to stay scannable; if the count is high, I show "Nx" with a representative site.

---

## 2. Per-table column census

### 2.1 `findings`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `fingerprint` | `src/store.ts:186` (UPSERT); many `UPDATE … WHERE fingerprint=?` | `src/store.ts:305, 317, 325, 387, 585, 820, 951, 1038, 1567` + 20+ consumers | live |
| `repo` | `src/store.ts:187` (UPSERT) | `src/store.ts:625, 632, 651, 754, 967, 1062, 1071, 1824` + e2e | live |
| `ref` | `src/store.ts:188` (UPSERT) | `src/store.ts:868` (StoredFindingRecord), `src/report-*` consumers | live |
| `task_id` | `src/store.ts:189`; mig 002/024 rename | `src/store.ts:783, 953`; consumed by every reporter + UI | live |
| `rule_id` | `src/store.ts:189` | `src/store.ts:784, 955, 1840` (regression detection); every reporter | live |
| `file_path` | `src/store.ts:190` | `src/store.ts:784, 956, 1824, 1840`; indexed + used in regression filter | live |
| `start_line` | `src/store.ts:191` | `src/store.ts:785, 957`; every reporter | live |
| `severity` | `src/store.ts:192` | `src/store.ts:785, 958`; every reporter | live |
| `message` | `src/store.ts:193` | `src/store.ts:785, 959`; reporters + UI | live |
| `verdict` | `src/store.ts:198, 1039` (UPDATE) | `src/store.ts:628, 630, 634, 757, 1039, 1843` + every reporter + review UI | live |
| `confidence` | `src/store.ts:199, 1041` | `src/store.ts:307, 817, 879, 961`; every reporter; verify-gate scoring | live |
| `rationale` | `src/store.ts:200` | `src/store.ts:308, 962`; every reporter + review UI | live |
| `verification_steps` | `src/store.ts:201` | `src/store.ts:373, 583, 785, 879, 963`; reporters | live |
| `fix_patch` | `src/store.ts:202` | `src/store.ts:374, 794, 888, 964`; `src/report-markdown.ts`, `src/patch.ts` consumers | live |
| `created_at` | default `datetime('now')` | no direct SELECT in live code; only `ORDER BY updated_at` is used | **write-only** (low risk — SQLite default, trivial to keep) |
| `updated_at` | many UPDATE sites keep it fresh | `src/store.ts:968, 1844` — `ORDER BY updated_at DESC` | live |
| `triage_cost_usd` | `src/store.ts:203` (UPSERT) | `src/store.ts:375, 649`, `getTotalCost` | live |
| `triage_details_json` | `src/store.ts:204–228` | `src/store.ts:376, 786, 880, 965`; `parseTriageDetails` + `getTriagedFindingsForRepo` | live (but big JSON bag — Agent 5 may want to extract) |
| `verify_exploitable` | `src/store.ts:1444` (UPDATE) | `src/store.ts:317, 586, 692, 795, 889`; gates verification skip | live |
| `verify_poc_payload` | `src/store.ts:1445` | `src/store.ts:579, 796, 890`; reporters | live |
| `verify_poc_description` | `src/store.ts:1446` | `src/store.ts:580, 797, 891`; reporters | live |
| `verify_attack_vector` | `src/store.ts:1447` | `src/store.ts:581, 798, 892`; UI `FindingCard`, reports | live |
| `verify_preconditions` | `src/store.ts:1448` | `src/store.ts:582, 799, 893`; reporters | live |
| `verify_confidence` | `src/store.ts:1449` | `src/store.ts:583, 800, 894`; reporters | live |
| `verify_cost_usd` | `src/store.ts:1450, 1468` | `src/store.ts:584, 801, 895`; `getTotalVerificationCost` is `_`-prefixed so only reporters count | live |
| `poc_harness_path` | `src/store.ts:1498` | `src/store.ts:326, 727, 802, 896`; reporters | live |
| `poc_harness_language` | `src/store.ts:1499` | `src/store.ts:803, 897`; reporters | live |
| `poc_harness_parsed` | `src/store.ts:1500` | `src/store.ts:804, 898`; reporters | live |
| `poc_harness_parse_error` | `src/store.ts:1501` | `src/store.ts:805, 899`; reporters | live |
| `poc_harness_skipped` | `src/store.ts:1502` | `src/store.ts:328, 725, 806, 900`; reporters | live |
| `poc_harness_skip_reason` | `src/store.ts:1503` | `src/store.ts:807, 901`; reporters | live |
| `poc_harness_cost_usd` | `src/store.ts:1504, 1527` | `src/store.ts:675, 808, 902`; `getTotalPocHarnessCost` | live |
| `poc_run_exit_code` | `src/store.ts:1505` | `src/store.ts:809, 903`; `src/report-json.ts:115`, `src/report-jsonl.ts:77` | live |
| `poc_run_stdout` | `src/store.ts:1506` | `src/store.ts:810, 904`; reporters | live |
| `poc_run_stderr` | `src/store.ts:1507` | `src/store.ts:811, 905`; reporters | live |
| `poc_run_verdict` | `src/store.ts:1508` | `src/store.ts:812, 906`; reporters | live |
| `poc_run_duration_ms` | `src/store.ts:1509` | `src/store.ts:813, 907`; reporters | live |
| `adjusted_score` | `src/store.ts:195` (upsert) | `src/store.ts:787, 881`; `src/report-sarif.ts:93` reads from StoredFindingRecord | live (but Agent 5 territory — overlaps `Finding.score`) |
| `corroboration_json` | `src/store.ts:196` | `src/store.ts:792, 840, 886` → `parseCorroboratingSignals` → SARIF/JSON reporters | live |
| `suppression_json` | `src/store.ts:197` | `src/store.ts:793, 841, 887` → SARIF reporter | live |
| `calibrated_confidence` | `src/confidence-calibration.ts:238` (`updateFindingCalibration`) | **No live SELECT.** Only `tests/confidence-calibration.test.ts:285`. In-memory `triageOutput.result.calibratedConfidence` is set right before the UPDATE and consumed from the JS object, never re-read from DB. | **write-only** (live writer, no live reader) |
| `evidence_chain_json` | `src/confidence-calibration.ts:238` | **No live SELECT.** Only `tests/confidence-calibration.test.ts:285`. Live code reads `triageOutput.result.evidenceChain` from the JS object, not the column. | **write-only** |
| `composite_confidence` | `src/store.ts:229` (UPSERT) + dead `_updateFindingCompositeConfidence:1411` | **No live SELECT.** Only `tests/e2e/run-e2e.sh:137–150, 214`. Live code reads `triageResult.compositeConfidence` in memory (`src/bus/orchestrator/verify-gate.ts:442`, `src/bus/orchestrator.ts:2918`). | **write-only** |
| `confidence_signals_json` | `src/store.ts:230` passes `null`; only non-null writer is dead `_updateFindingCompositeConfidence:1411`. Column is never populated in live code. | **No readers anywhere** (not even tests). | **dead** |
| `taint_path_json` | `src/store.ts:231` | `src/store.ts:788, 836, 882` → `parseTaintPath` → `StoredFindingRecord.taintPath`; consumed by UI, reporters, `patch.ts` | live |
| `proof_state` | `src/store.ts:232, 1555` (`updateFindingProofState`) | `src/store.ts:789, 837, 883, 1541`; `src/report-sarif.ts:94`, enrichment, dynamic-analysis, verify-gate | live |
| `engine_provenance_json` | `src/store.ts:233` | `src/store.ts:790, 838, 884`; SARIF + strategy merge | live |
| `finding_metadata_json` | `src/store.ts:234` (COALESCE) + `updateFindingMetadata:1590` | `src/store.ts:791, 839, 885, 1567, 1570`; `src/patch.ts:682` consumes `finding.findingMetadata` | live |

### 2.2 `pipeline_runs`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `run_id` | `src/store.ts:1085` (INSERT) | PK in every SELECT; `src/store.ts:1604, 1641, 1676, 1693` | live |
| `repo` | `src/store.ts:1090` | `src/store.ts:1619, 1655`, monorepo prefix match | live |
| `started_at` | `src/store.ts:1092` | `src/store.ts:1620, 1656` — `ORDER BY started_at DESC` | live |
| `status` | `src/store.ts:1085, 1108, 1813` | `src/store.ts:1619, 1656, 1706, 1813` | live |
| `config_json` | `src/store.ts:1093` | SELECTed in `getRun`/`getLatestResumableRun`; consumed by resume path `src/bus/orchestrator.ts` | live |
| `scan_opts_json` | `src/store.ts:1094` | SELECTed in `getRun`/`getLatestResumableRun`; consumed by resume path | live |
| `findings_json` | `src/store.ts:1116, 1143` | `src/store.ts:1611, 1647, 1683, 1704–1710` → `getLatestCompletedRunFindings`; `src/bus/orchestrator.ts:604`, `src/report-sarif.ts:64` | live (Agent 5 concern: snapshot of live rows) |
| `total_cost_usd` | `src/store.ts:1397` (`updateRunCost`) | SELECTed in `getRun`/`getLatestResumableRun`; used in monorepo summary | live |
| `completed_at` | `src/store.ts:1121, 1126, 1813` | `src/store.ts:1706` `ORDER BY COALESCE(completed_at, started_at)`; `src/incremental.ts:16` | live |
| `updated_at` | touched on every UPDATE | SELECTed into record; not directly consumed but useful for debugging | live |
| `context_json` | `src/store.ts:1151` (`updateRunContext`) | `src/store.ts:1612, 1648, 1684`; `src/bus/orchestrator.ts:596` resumes from it | live |
| `metrics_json` | `src/store.ts:1420` (`updateRunMetrics`) | `src/store.ts:1616, 1652, 1688`; `src/cli.ts:282` (run-compare) | live |
| `assertions_json` | **only `_updateRunAssertions:1799` (dead)** | `src/store.ts:1617, 1653, 1689`; `src/cli.ts:313` | **write-only** (never populated; `run-compare` always sees `null`) |
| `prompt_hash` | **only `_updatePromptHash:1792` (dead)** | `src/store.ts:1618, 1654, 1690`; `src/cli.ts:290` | **write-only** (never populated) |
| `head_ref` | `src/incremental.ts:33` (`UPDATE pipeline_runs SET head_ref = ?`) | `src/incremental.ts:16` (`SELECT head_ref …`) | live |

### 2.3 `calibration_weights`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `step_type` | `src/confidence-calibration.ts:173` | `src/confidence-calibration.ts:88, 99, 112, 118, 186` | live |
| `rule_family` | `src/confidence-calibration.ts:173` | same as above | live |
| `weight` | `src/confidence-calibration.ts:176, 196` | `src/confidence-calibration.ts:88, 149, 186` | live |
| `sample_count` | `src/confidence-calibration.ts:178` | SELECTed; used in format/prune | live |
| `updated_at` | `src/confidence-calibration.ts:180` | SELECTed (not consumed beyond populating `updatedAt` field) | live |

### 2.4 `trajectories`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `id` | `src/trajectory-memory.ts:170` | PK; pruning `NOT IN (SELECT id …)` at `:367` | live |
| `rule_id` | `:171` | `ORDER BY`/`WHERE rule_id = ?` at `:221, 244, 275, 345`; `t.ruleId` in `formatTrajectoriesForPrompt:322` | live |
| `cwes_json` | `:172` | `WHERE cwes_json LIKE ?` at `:244, 271` | live (but only via LIKE — Agent 5 may want CWE as a proper many-to-many) |
| `task_id` | `:173` | SELECTed by `SELECT *` into `TrajectoryRecord.taskId`; **no consumer reads `.taskId`** | **write-only** |
| `verdict` | `:173` | `t.verdict` in formatter `:322` | live |
| `confidence` | `:174` | SELECTed into `TrajectoryRecord.confidence`; **no consumer reads `.confidence`** | **write-only** |
| `was_correct` | INSERT `NULL` at `:168`; UPDATE at `:200` | `:225, 247, 276, 345, 385`; `t.wasCorrect` at `formatTrajectoriesForPrompt:302` | live |
| `steps_json` | `:175` | `t.stepsJson` at `:308` → parsed + formatted | live |
| `summary` | `:176` | `t.summary` at `:323` | live |
| `repo` | `:177` | SELECTed into `TrajectoryRecord.repo`; **no consumer reads `.repo`** | **write-only** |
| `fingerprint` | `:178` | `WHERE fingerprint = ?` in `updateTrajectoryCorrectness:199` | live |
| `created_at` | `:180` | `:385` (prune threshold) | live |
| `updated_at` | `:181, 199` | `ORDER BY updated_at DESC` in every retrieval | live |

### 2.5 `finding_assertions`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `id` | AUTOINCREMENT (implicit) | **Only `_getRunAssertions:1759` (dead)**. No live consumer. | **write-only** |
| `run_id` | `src/store.ts:1752` (`saveAssertionResults`) | same | **write-only** |
| `fingerprint` | `:1752` | same | **write-only** |
| `assertion_name` | `:1752` | same | **write-only** |
| `passed` | `:1752` | same | **write-only** |
| `score` | `:1752` | same | **write-only** |
| `weight` | `:1752` | same | **write-only** |
| `reason` | `:1752` | same | **write-only** |
| `created_at` | DB default | same | **write-only** |

The **whole table** is write-only in live code. Writer runs by default (`triageAssertions.enabled !== false`). Reader is `_getRunAssertions` which no caller invokes. See §4.

### 2.6 `dynamic_analysis_runs`

All columns — writer `insertDynamicAnalysisRun` at `src/store/dynamic-analysis.ts:31` is called from `src/bus/workers/dynamic-analysis-worker.ts:402`. Readers `getDynamicAnalysisRun:67` and `getDynamicRunsForFinding:80` are exported but **not called anywhere** in `src/` or `tests/`. The row-mapper `rowToDynamicAnalysisRun` therefore never runs. See §4.

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `dynamic_run_id` … `updated_at` (all 23) | `insertDynamicAnalysisRun:31–64` | **None in live code**; `rowToDynamicAnalysisRun` is unreachable. | **write-only table** |

`finding_metadata_json.latestDynamicRunId` / `dynamicRunIds` (stored on `findings`) retains the pointers but does not dereference them.

### 2.7 `patch_results`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `patch_run_id` | `src/store/patch-results.ts:30` (INSERT); `:97` (UPDATE WHERE) | `:50` (`WHERE patch_run_id = ?`); `tests/bus/patch-verify-worker.test.ts` | live |
| `fingerprint` | `:31` | `:63` (`WHERE fingerprint = ?`); `src/bus/workers/patch-verify-worker.ts:46`, `src/bus/orchestrator/patch-dispatcher.ts:115` | live |
| `repo` | `:32` | SELECT *; mapped into `PatchResult.repo`; consumed in patch result display | live |
| `diff` | `:33` | same → `PatchResult.diff` | live |
| `status` | `:34, 97` (`updatePatchResultStatus`) | `:50, 63` → consumers in orchestrator gate | live |
| `iterations` | `:35` | → `PatchResult.iterations` used in reporting | live |
| `build_command` | `:36` | → `PatchResult.buildCommand` | live |
| `test_command` | `:37` | → `PatchResult.testCommand` | live |
| `worktree_path` | `:38` | → `PatchResult.worktreePath`; `src/bus/workers/patch-verify-worker.ts` uses it | live |
| `cost_usd` | `:39` | → cost sum | live |
| `validator_log` | `:40` | → displayed on failure | live |
| `history_json` | `:41` | → `PatchResult.history` consumed by UI/logs | live |
| `created_at` | default | `ORDER BY created_at DESC` at `:64` | live |
| `updated_at` | default/UPDATE | SELECT * → `updatedAt` field; not directly rendered but used by row mapper | live |

### 2.8 `crypto_behavioral_runs`

Writer `insertCryptoBehavioralRun` called from `src/agents/tasks/crypto-behavioral-test.ts:202`. The only reader `getCryptoBehavioralRunsByFingerprint:73` is called **only from the test** `tests/store/crypto-behavioral.test.ts:63`. No live code reads this table.

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `run_id` | `src/store/crypto-behavioral.ts:45` | test only | **write-only table** |
| `pipeline_run_id` | `:46` | test only | **write-only table** |
| `fingerprint` | `:47` | test only | **write-only table** |
| `repo` | `:48` | test only | **write-only table** |
| `test_type` | `:49` | test only | **write-only table** |
| `verdict` | `:50` | test only | **write-only table** |
| `harness_path` | `:51` | test only | **write-only table** |
| `harness_language` | `:52` | test only | **write-only table** |
| `execution_exit_code` | `:53` | test only | **write-only table** |
| `execution_verdict` | `:54` | test only | **write-only table** |
| `execution_stdout` | `:55` | test only | **write-only table** |
| `execution_stderr` | `:56` | test only | **write-only table** |
| `execution_duration_ms` | `:57` | test only | **write-only table** |
| `t_statistic` | `:58` | test only | **write-only table** |
| `p_value` | `:59` | test only | **write-only table** |
| `mean_a_ns` | `:60` | test only | **write-only table** |
| `mean_b_ns` | `:61` | test only | **write-only table** |
| `timing_iterations` | `:62` | test only | **write-only table** |
| `observed_behavior` | `:63` | test only | **write-only table** |
| `expected_behavior` | `:64` | test only | **write-only table** |
| `algorithm_confirmed` | `:65` | test only | **write-only table** |
| `key_length_bits` | `:66` | test only | **write-only table** |
| `cost_usd` | `:67` | test only | **write-only table** |
| `metadata_json` | `:68` | test only | **write-only table** |
| `created_at` | `:69` | test only | **write-only table** |
| `updated_at` | `:70` | test only | **write-only table** |

### 2.9 `code_graph_nodes`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `node_id` | `src/agents/tasks/code-graph/store.ts:55` | PK filter at `:155, 194`; rowToNode | live |
| `repo` | `:56` | filter at `:132, 141, 155, 194` | live |
| `run_id` | `:57` | **No WHERE filter, no rowToNode read** — written only (UPDATE on conflict refreshes it). No SELECT ever projects `run_id`. | **write-only** |
| `file_path` | `:58` | `:140, 155, 230`; rowToNode consumed | live |
| `start_line` | `:59` | `:155`; rowToNode consumed | live |
| `symbol` | `:60` | rowToNode | live |
| `node_kind` | `:61` | `:140` entry filter; rowToNode consumed by enrichment | live |
| `framework` | `:62` | rowToNode → `CodeGraphNode.framework`; consumed in traversal/prompts | live |
| `metadata_json` | `:63` | rowToNode → `.metadata` | live |
| `confidence` | `:64` | rowToNode → `.confidence` | live |
| `source` | `:65` | rowToNode → `.source` | live |
| `created_at` | default | not selected by any reader (rowToNode omits) | **write-only** (low risk) |
| `updated_at` | default/UPDATE | not selected | **write-only** (low risk) |

### 2.10 `code_graph_edges`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `edge_id` | `:83` | rowToEdge (`.edgeId`) — consumed in `enrich.ts`/path reconstruction | live |
| `repo` | `:84` | `WHERE repo = ?` in `invalidateStaleNodes` | live |
| `run_id` | `:85` | **No SELECT reads it.** | **write-only** |
| `from_node_id` | `:86` | `WHERE from_node_id = ?` at `:180`; FK integrity | live |
| `to_node_id` | `:87` | `WHERE to_node_id = ?` at `:187`; FK integrity | live |
| `edge_kind` | `:88` | rowToEdge → `.edgeKind` | live |
| `data_label` | `:89` | rowToEdge → `.dataLabel` | live |
| `ordinal` | `:90` | rowToEdge → `.ordinal` | live |
| `confidence` | `:91` | rowToEdge → `.confidence` | live |
| `source` | `:92` | rowToEdge → `.source` | live |
| `created_at` | default | not selected | **write-only** (low risk) |

### 2.11 `code_graph_paths`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `path_id` | `:109` | PATH_COLUMNS rowToPath | live |
| `repo` | `:110` | `WHERE repo = ?` | live |
| `run_id` | `:111` | **No SELECT reads it.** | **write-only** |
| `entry_node_id` | `:112` | rowToPath → `.entryNodeId`; used in `enrich.ts:105` | live |
| `target_node_id` | `:113` | `WHERE target_node_id = ?` at `:172`; rowToPath | live |
| `hop_count` | `:114` | `ORDER BY hop_count ASC` at `:172`; rowToPath | live |
| `path_node_ids` | `:115` | rowToPath → `.nodeIds` | live |
| `path_edge_ids` | `:116` | rowToPath → `.edgeIds` | live |
| `has_sanitizer` | `:117` | rowToPath → `.hasSanitizer`; enrichment penalty | live |
| `sanitizer_nodes` | `:118` | rowToPath → `.sanitizerNodeIds`; `enrich.ts:107` | live |
| `confidence` | `:119` | rowToPath | live |
| `created_at` | default | not selected | **write-only** (low risk) |

### 2.12 `workspaces`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `id` | `src/workspace/manager.ts:17` (INSERT) | `WHERE id = ?` at `:23, 67, 79`; rowToWorkspace | live |
| `name` | `:17, 62` | `WHERE name = ?` at `:30`; rowToWorkspace | live |
| `targets_json` | `:17, 62` | rowToWorkspace → `.targets`; used by `addTarget` | live |
| `created_at` | `:17` | rowToWorkspace → `.createdAt` | live |
| `last_accessed_at` | `:17, 79` (`touchAccessed`) | `ORDER BY last_accessed_at DESC` at `:44`; rowToWorkspace | live |
| `metadata_json` | `:17, 62` | rowToWorkspace → `.metadata` | live |
| `updated_at` | `:62` | **No SELECT reads it** — rowToWorkspace omits it. | **write-only** (low risk) |

### 2.13 `workspace_snapshots`

| Column | Write sites | Read sites | Status |
|---|---|---|---|
| `id` | AUTOINCREMENT | `ORDER BY id DESC LIMIT 1` at `:91` (in `loadLatestSnapshot`) | live (but see §4 — table is never populated in live code) |
| `workspace_id` | `:85` (`saveSnapshot`) | `WHERE workspace_id = ?` at `:91` | table-unused (see §4) |
| `snapshot_json` | `:85` | `:91` — returned to caller | table-unused |
| `created_at` | default | not selected | **write-only** |

`saveSnapshot` is only invoked from `tests/workspace/manager.test.ts`. Live code calls `loadLatestSnapshot` (which will always get no rows) but never writes. Effectively a dead table. See §4.

### 2.14 `schema_version`

Bookkeeping table managed by `src/migrations/runner.ts`. Columns `version`, `name`, `applied_at`. Read and written by the runner on every boot. Live.

### 2.15 `intel_documents` + `intel_fts`

All columns on `intel_documents` (`id`, `source`, `title`, `content`, `metadata_json`, `ingested_at`) are written by `SqliteIntelStore.ingest/ingestBatch` and read by `search/get/count/clearSource`. Activated from `src/cli.ts:852, 891, 922`. Live.

`intel_fts` is an FTS5 mirror populated by triggers; used in `SqliteIntelStore.search`. Live.

---

## 3. Drop list

Grouped by confidence. Each entry is one sentence justification + top evidence.

### HIGH — zero real reads, full audit confirms nothing breaks

| # | Table.column | Rationale |
|---|---|---|
| H1 | `findings.confidence_signals_json` | Never written to a non-null value in live code (`src/store.ts:230` writes `null`; only writer is dead `_updateFindingCompositeConfidence:1411`). Never SELECTed anywhere — not even in tests. Pure migration artifact. |
| H2 | `findings.calibrated_confidence` | Written only by `updateFindingCalibration` (`src/confidence-calibration.ts:238`). No SELECT in live code; only `tests/confidence-calibration.test.ts:285`. Runtime calibration uses the in-memory `triageOutput.result.calibratedConfidence` set at `src/bus/workers/triage-worker.ts:414`. |
| H3 | `findings.evidence_chain_json` | Same writer as H2; no live reader. Only `tests/confidence-calibration.test.ts:285` reads it. |
| H4 | `findings.composite_confidence` | Written on upsert at `src/store.ts:229`. No live SELECT — only `tests/e2e/run-e2e.sh` and dead `_updateFindingCompositeConfidence`. Runtime uses in-memory `triageResult.compositeConfidence`. |
| H5 | `pipeline_runs.assertions_json` | Only writer is dead `_updateRunAssertions:1799`; column is always `null`. `src/cli.ts:313` reads it into a run-compare tool that therefore always sees null. |
| H6 | `pipeline_runs.prompt_hash` | Same pattern as H5 — only writer `_updatePromptHash:1792` is dead. `src/cli.ts:290` always sees null. |
| H7 | `trajectories.task_id` | Written at `src/trajectory-memory.ts:173`; SELECTed into `TrajectoryRecord.taskId` but **no consumer reads the field** (I checked every use of `TrajectoryRecord`). |
| H8 | `trajectories.confidence` | Same — stored but never consumed anywhere. |
| H9 | `trajectories.repo` | Same — stored but never used in `formatTrajectoriesForPrompt` or any other consumer. |
| H10 | `code_graph_nodes.run_id` | Written on insert; updated on conflict. No SELECT projects or filters on it. |
| H11 | `code_graph_edges.run_id` | Same. |
| H12 | `code_graph_paths.run_id` | Same. |

### MEDIUM — flag-gated or "write-only table"

| # | Table.column | Rationale |
|---|---|---|
| M1 | `finding_assertions` **entire table** | Writer `saveAssertionResults` runs by default (`triageAssertions.enabled !== false` in `src/bus/workers/triage-worker.ts:519`), but the reader `_getRunAssertions:1759` is dead. The table is write-only in production and consumes disk for no reader. Drop the table (and remove `saveAssertionResults` + the `triage:assertions` handler) unless a future UI surfaces these. Flag M because the data is cheap to regenerate and some future UI intent is plausible. |
| M2 | `crypto_behavioral_runs` **entire table** | Writer runs when user enables `crypto-behavioral-test` task (not default). Reader `getCryptoBehavioralRunsByFingerprint` is only called from tests. Data pointer survives via `findingMetadata` text on `findings` row. Drop the table unless a future feature reads it. |
| M3 | `dynamic_analysis_runs` **entire table** | Writer `insertDynamicAnalysisRun` is called from the dynamic-analysis worker; readers `getDynamicAnalysisRun` / `getDynamicRunsForFinding` have **zero callers** in `src/` and `tests/`. The worker also updates `findings.finding_metadata_json` with `latestDynamicRunId` / `dynamicRunIds`, but nothing ever dereferences those IDs. Drop the table unless a UI surface is planned; if so, Agent 5 should decide whether to extract a thinner summary column on `findings`. |
| M4 | `workspace_snapshots` **entire table** | `saveSnapshot` is never called from `src/`. Live code calls `loadLatestSnapshot` but always gets `null`. If persistent workspace snapshots are actually desired, the write path is a bug to fix; otherwise drop the table. |

### LOW — plausibly-live timestamps that nothing reads today but are almost-free to keep

| # | Table.column | Rationale |
|---|---|---|
| L1 | `findings.created_at` | SQLite-defaulted; no live SELECT consumes it (`updated_at` handles ordering). Cheap to keep; dropping it would change row size by ~20 bytes. Recommend KEEP. |
| L2 | `code_graph_nodes.created_at` / `updated_at` | No SELECT projects either. Cheap to keep. Recommend KEEP. |
| L3 | `code_graph_edges.created_at` | Same. Recommend KEEP. |
| L4 | `code_graph_paths.created_at` | Same. Recommend KEEP. |
| L5 | `workspaces.updated_at` | Written by `update()`; not selected. Recommend KEEP (symmetry with `created_at`). |

I **do not** recommend dropping L1–L5 — listing them for completeness because the brief asked for suspicious-but-retained refs. They are cheap DB hygiene and future `ORDER BY created_at` is plausible.

---

## 4. Dead-table candidates

| Table | Reason |
|---|---|
| `finding_assertions` | Writer is live, every reader is dead. See M1. |
| `crypto_behavioral_runs` | Writer runs on opt-in task; no live reader. See M2. |
| `dynamic_analysis_runs` | Writer is live; every reader is unreferenced. See M3. |
| `workspace_snapshots` | Writer is never invoked from `src/`; reader always returns null. See M4. |

Each of these is a *structural* drop (Agent 5 territory for crypto / dynamic / snapshots — extracting summary scalars onto parent rows). Agent 2 flags; Agent 5 decides extract-vs-drop.

`code_graph_paths` is a borderline case — its *columns* are all live, so it stays. But `run_id` across all three `code_graph_*` tables is dead (H10–H12).

---

## 5. Cross-cutting observations (flag, do not resolve)

1. **`findings.triage_details_json` is a grab-bag JSON blob.** `src/store.ts:204–228` serializes 12 fields into it (`title`, `attack_narrative`, `display_severity`, `source`, `sink`, `is_vulnerable`, `exploit_scenario`, `recommended_fix`, `rule_refinement_hint`, `triage_schema_version`, `code_citations`, `attack_path`, `assumptions`, `controls`, `blindspots`, `source_threat_ids`). Everything is live (consumed via `parseTriageDetails` → `StoredFindingRecord`). **Agent 5**: candidates for extraction to scalar columns include `title`, `display_severity`, `is_vulnerable`, `exploit_scenario`, `recommended_fix`, `triage_schema_version`. Sub-objects (`source`, `sink`, `attack_path`, `code_citations`) stay JSON.

2. **`findings.finding_metadata_json` carries pointer IDs to dead tables.** `updateFindingMetadata` merges `latestDynamicRunId` / `dynamicRunIds` / `latestPatchRunId` / `patchRunIds` / `latestDynamicStatus` / `notes` / `blame` / `introducedIn`. Only `blame` and `introducedIn` are read by a live consumer (`getActionableFindings:924-927`). The dynamic/patch run IDs point at `dynamic_analysis_runs` / `patch_results` rows — if Agent 5 decides to keep `patch_results` but drop `dynamic_analysis_runs`, the metadata should likewise drop dynamic pointers. **Agent 5**: consider extracting `blame.sha` + `introduced_in` to their own scalar columns, since they're the only live reads.

3. **`adjusted_score` is live (reporters use it via SARIF)** but it duplicates `score` unless an FP filter / code-graph sanitizer penalty has run. Agent 5 territory — see `_column-ownership.md:43`.

4. **`pipeline_runs.findings_json`** snapshots ranked findings at completion. Agent 5 territory — snapshot-vs-live concern. (Note: it is the ONLY source of `Finding[]` for e.g. monorepo cross-repo aggregation, so don't blindly drop it.)

5. **`trajectories.cwes_json` is consumed only via `LIKE` matching.** Functional but structurally awkward (non-indexed substring search on a JSON string). Agent 5 may want a `trajectory_cwes(trajectory_id, cwe)` junction, but that is denormalization territory.

6. **H1 (`confidence_signals_json`) is ALSO a candidate Agent 5 might want to resurrect.** The original intent of `_updateFindingCompositeConfidence` was to persist the per-scanner/per-triage signal weights. If Agent 5 decides compositeConfidence should be recomputable from source signals, they may want to materialize `confidence_signals_json` instead of dropping `composite_confidence`. For A2's purposes, both are dead today — A5 gets to override.

7. **`finding_assertions` rows are cheap to regenerate** (pure function of triage result). If any UI surfaces triage quality later, they can be recomputed on read. The table's *write-only-ness today* should not be a blocker to dropping — that's the point of the write-only flag.

8. **`dynamic_analysis_runs` + `crypto_behavioral_runs` are write-only but contain substantive runtime evidence.** Agent 5 may prefer to extract a one-field summary onto `findings` (e.g. `dynamic_verdict`, `crypto_verdict`) and drop the detail tables, or vice versa. A2's drop recommendation is "drop unless A5 says keep."

9. **`PRAGMA foreign_keys = ON` is not set** (verified via `Grep` in `src/store.ts`'s `initDb`). This affects Agent 4's constraint work; I mention it only because several FKs (`workspace_snapshots.workspace_id → workspaces.id`, `code_graph_edges.{from,to}_node_id → code_graph_nodes.node_id`, `code_graph_paths.{entry,target}_node_id → code_graph_nodes.node_id`) are declared but not enforced.

---

## 6. Draft SQL

### Full-reset policy (recommended per Phase-C plan)

The v100 `CREATE TABLE` statements simply **omit** every HIGH-confidence dropped column and every dead table. Agent 3 owns the reset mechanism; this section enumerates what to *not* include in `100_schema_reset.ts`:

```
-- DROPPED COLUMNS (do not include in v100 CREATE TABLE findings):
--   findings.confidence_signals_json           (H1)
--   findings.calibrated_confidence             (H2)
--   findings.evidence_chain_json               (H3)
--   findings.composite_confidence              (H4)

-- DROPPED COLUMNS (do not include in v100 CREATE TABLE pipeline_runs):
--   pipeline_runs.assertions_json              (H5)
--   pipeline_runs.prompt_hash                  (H6)

-- DROPPED COLUMNS (do not include in v100 CREATE TABLE trajectories):
--   trajectories.task_id                       (H7)
--   trajectories.confidence                    (H8)
--   trajectories.repo                          (H9)

-- DROPPED COLUMNS (do not include in v100 CREATE TABLE code_graph_*):
--   code_graph_nodes.run_id                    (H10)
--   code_graph_edges.run_id                    (H11)
--   code_graph_paths.run_id                    (H12)

-- DROPPED TABLES (do not CREATE in v100, subject to A5 override):
--   finding_assertions                         (M1)
--   crypto_behavioral_runs                     (M2)
--   dynamic_analysis_runs                      (M3)
--   workspace_snapshots                        (M4)
```

### `ALTER TABLE` form (for reference only — not used under reset policy)

Kept here so that a non-reset path (or a future incremental drop) has exact syntax. SQLite ≥ 3.25 supports `ALTER TABLE … DROP COLUMN`; Node 22 ships ≥ 3.45.

```sql
-- HIGH-confidence column drops on `findings`
ALTER TABLE findings DROP COLUMN confidence_signals_json;
ALTER TABLE findings DROP COLUMN calibrated_confidence;
ALTER TABLE findings DROP COLUMN evidence_chain_json;
ALTER TABLE findings DROP COLUMN composite_confidence;

-- HIGH-confidence column drops on `pipeline_runs`
ALTER TABLE pipeline_runs DROP COLUMN assertions_json;
ALTER TABLE pipeline_runs DROP COLUMN prompt_hash;

-- HIGH-confidence column drops on `trajectories`
ALTER TABLE trajectories DROP COLUMN task_id;
ALTER TABLE trajectories DROP COLUMN confidence;
ALTER TABLE trajectories DROP COLUMN repo;

-- HIGH-confidence column drops on `code_graph_*`
ALTER TABLE code_graph_nodes DROP COLUMN run_id;
ALTER TABLE code_graph_edges DROP COLUMN run_id;
ALTER TABLE code_graph_paths DROP COLUMN run_id;

-- MEDIUM-confidence table drops (subject to A5 override)
DROP TABLE IF EXISTS finding_assertions;
DROP TABLE IF EXISTS crypto_behavioral_runs;
DROP TABLE IF EXISTS dynamic_analysis_runs;
DROP TABLE IF EXISTS workspace_snapshots;
```

### Follow-on code cleanup implied by accepting the drops

These are not SQL, but will need to land in Phase C Commits 2/3:

- `src/store.ts`: delete dead functions `_updateFindingCompositeConfidence`, `_updateRunAssertions`, `_updatePromptHash`, `_getRunAssertions`; delete `saveAssertionResults` if M1 accepted.
- `src/confidence-calibration.ts:230` (`updateFindingCalibration`): if H2/H3 accepted, drop the function (keep in-memory calibration logic).
- `src/bus/workers/triage-worker.ts:416-421`: drop the `updateFindingCalibration(...)` call.
- `src/bus/workers/triage-worker.ts:518-547`: drop the assertion save path if M1 accepted.
- `src/bus/workers/store-worker.ts:78-82`: drop `triage:assertions` subscriber if M1 accepted.
- `src/store/dynamic-analysis.ts`: delete entirely if M3 accepted.
- `src/store/crypto-behavioral.ts`: delete entirely if M2 accepted.
- `src/workspace/manager.ts:82-100` (`saveSnapshot`, `loadLatestSnapshot`): delete if M4 accepted.
- `src/cli.ts:282-291, 313-314`: update run-compare to not read `assertionsJson` / `promptHash`.
- `tests/confidence-calibration.test.ts:265-320`: delete the DB-level subtests for H2/H3.
- `tests/bus/patch-verify-worker.test.ts`: unaffected.
- `tests/store/crypto-behavioral.test.ts`: delete if M2 accepted.
- `tests/workspace/manager.test.ts:105-145`: delete snapshot subtests if M4 accepted.
- `tests/e2e/run-e2e.sh:137-150, 214`: drop composite_confidence phase-1E checks if H4 accepted.

---

## Verification

- Every HIGH-confidence drop was verified with **two greps** (snake_case and camelCase) against both `src/` and `tests/`, plus a check that any row-mapper that SELECTs the column is actually reached. The writes-only-by-dead-function pattern was confirmed by checking that every writer is either (a) `_`-prefixed (convention for "unused"), or (b) reads back an in-memory object instead of re-reading the DB.
- The four dead-table candidates were each confirmed by looking up every exported function in the store module and verifying no live `src/` code imports it.
- Agent 5 cross-cutting flags are called out in §5 so structural overrides can win in Phase B (precedence in `_column-ownership.md:48`).
