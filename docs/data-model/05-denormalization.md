# 05 — Denormalization Cleanup (Agent 5)

Scope: decide which data on `findings` / `pipeline_runs` belongs as scalar columns, as joined side-tables, or as JSON blobs; collapse split update paths; remove redundant columns.

All evidence citations are `path:line`. Code was **not** modified.

---

## 1. `adjustedScore` audit

### Write sites

| Site | Formula | Evidence |
|---|---|---|
| Scan merge (ensemble corroboration) | `adjustedScore = min(100, baseScore + corroborationBoost)` where `corroborationBoost = min(15, max(0, corroboratingModels-1) * 5)` | `src/bus/workers/scan-worker.ts:246-251` |
| FP filter (default) | `adjustedScore = finding.score` when no suppression matches | `src/scanners/fp-filter.ts:183-188` (`ensureAdjustedScore`) |
| FP filter (suppression hit) | `adjustedScore = max(0, base.adjustedScore ?? base.score) - totalPenalty` (soft penalties only) | `src/scanners/fp-filter.ts:202-210` |
| Multi-strategy merge | `max(finding.adjustedScore ?? finding.score, strategyMatch.adjustedScore ?? strategyMatch.score)` | `src/strategies/multi-strategy-task.ts:97-100` |
| Ensemble merge (strategies) | `min(100, best.adjustedScore ?? best.score + confidenceBoost*100)` | `src/strategies/merge.ts:138-141` |
| Code-graph enrich | `max(0, (finding.adjustedScore ?? finding.score) - scorePenalty - sanitizerPenalty)` | `src/agents/tasks/code-graph/enrich.ts:171-174` |
| Reachability check | `max(0, (finding.adjustedScore ?? finding.score) - scorePenalty)` | `src/agents/tasks/reachability-check.ts:194` |
| DB upsert | `finding.adjustedScore ?? finding.score` (coalesces to `score` before insert) | `src/store.ts:195` |

### Read sites

| Site | Usage | Evidence |
|---|---|---|
| Sorting / primary ranking | `getFindingScore(finding) => finding.adjustedScore ?? finding.score` (seven call sites apply this coalesce) | `src/bus/workers/scan-worker.ts:278-280`; `src/scanners/normalization.ts:86-87`; `src/agents/tasks/call-graph-assist.ts:44`; `src/bus/orchestrator.ts:3243`; `src/cli/commands/monorepo-scan.ts:965`; `src/bus/workers/dynamic-analysis-worker.ts:384` |
| Actionable findings load-back | `SELECT adjusted_score as adjustedScore` → returned on `StoredFindingRecord.adjustedScore` | `src/store.ts:787,881` |
| SARIF export | `finding.adjustedScore ?? undefined` | `src/report-sarif.ts:93` |
| Tests | directly asserted in `tests/scanners/fp-filter.test.ts`, `tests/strategies/merge.test.ts`, `tests/store.test.ts` | as cited |

### Finding

`adjustedScore` is **genuinely different from `score`** — corroboration boosts, FP/suppression penalties, reachability penalties, code-graph sanitizer penalties, and strategy merges all modify it independently of `score`. The **unconditional** `?? score` fallback pattern at read-time is the bug: it means any finding that *wasn't* adjusted round-trips through the DB with `adjusted_score = score` (upsert line 195 falls back to `score` when undefined), producing a stored value that could instead be `NULL`.

### Recommendation

**Keep** `adjusted_score` — it is a distinct risk signal. But **change the upsert**:

- Replace `finding.adjustedScore ?? finding.score` with `finding.adjustedScore ?? null` so the column only holds *actual* adjustments, not a shadow copy of `score`. Readers already use `?? score` pattern, so migrating to nullable storage is transparent on the read side.
- Alternative (rejected): compute `adjusted_score` lazily as `GENERATED ALWAYS AS (COALESCE(raw_adjusted_score, score)) VIRTUAL`. SQLite supports this, but it hides the "was this ever actually adjusted?" signal from aggregate queries. Prefer the simpler nullable approach.

Cross-ref to A2: Agent 2's "adjusted_score written once, never read meaningfully" finding is **wrong**. Readers do consume it. Do **not** drop.

---

## 2. JSON column triage

The 13 JSON/near-JSON columns currently on `findings` (the plan says 12; I count `triage_details_json`, `verify_poc_*` group, `poc_harness_*` group, `poc_run_*` group, `evidence_chain_json`, `corroboration_json`, `suppression_json`, `composite_confidence`, `confidence_signals_json`, `taint_path_json`, `engine_provenance_json`, `finding_metadata_json`, plus `calibrated_confidence` is scalar — matching the plan's "12 JSON-blob columns" list). `verify_poc_*`, `poc_harness_*`, and `poc_run_*` are **not** JSON — they are scalar columns grouped by prefix; I include them because the plan enumerates them. `composite_confidence` is scalar too. True JSON columns are bolded.

| Column | Current shape (from write site) | Stable fields | Recommendation | Target |
|---|---|---|---|---|
| **`triage_details_json`** | `{ title, attack_narrative, display_severity, source: {why, evidence, isFalsePositive}, sink: {…}, is_vulnerable, exploit_scenario, recommended_fix, rule_refinement_hint, triage_schema_version, code_citations: CodeCitation[], attack_path: {chain, narrative, likelihood_reasoning, impact_reasoning}, assumptions: string[], controls: SecurityControl[], blindspots: string[], source_threat_ids: string[] }` (`src/store.ts:204-228`) | All top-level fields are stable; `code_citations`, `controls`, `source_threat_ids` are 1-to-N | **Extract (partial)** | Promote scalar fields (`title`, `attack_narrative`, `display_severity`, `is_vulnerable`, `exploit_scenario`, `recommended_fix`, `rule_refinement_hint`, `triage_schema_version`) to columns; extract `source`/`sink` as embedded JSON or pairs of columns; extract `code_citations`, `controls` into side-tables (see §5); keep `assumptions`, `blindspots`, `source_threat_ids` as TEXT JSON arrays because they are unstructured text lists |
| **`corroboration_json`** | `CorroboratingSignal[]`: `[{ taskId, fingerprint, ruleId, filePath, startLine, cwe: string[], score }]` (`src/store.ts:196`, type at `src/scanners/types.ts:8-16`) | All fields stable; 1-to-N per finding | **Extract** | New `finding_corroborations` side-table (see §5) |
| **`suppression_json`** | `SuppressionReason[]`: `[{ id, kind: 'hard'|'soft', description, scorePenalty? }]` (`src/store.ts:197`, type at `src/scanners/types.ts:18-23`) | All fields stable; 1-to-N per finding | **Extract** | New `finding_suppressions` side-table (see §5) |
| **`taint_path_json`** | `TaintPathStep[]`: `[{ filePath, line, message?, snippet? }]` (`src/store.ts:231`, type at `src/scanners/types.ts:25-30`) | All fields stable; ordered 1-to-N per finding | **Extract** | New `finding_taint_steps` side-table with `step_index` for ordering (see §5) |
| **`engine_provenance_json`** | `EngineProvenance[]`: `[{ kind: 'semgrep'\|'codeql'\|'taint-analysis'\|'agentic'\|'dynamic', detail }]` (`src/store.ts:233`, type at `src/scanners/types.ts:39-42`) | 2 fields, closed-enum `kind`, 1-to-N | **Extract** | New `finding_engines` side-table (see §5) |
| **`evidence_chain_json`** | `EvidenceStep[]`: `[{ stepType, description, confidence, evidence }]` (`src/confidence-calibration.ts:238-240`, type at `src/types.ts:98-103`) | All fields stable; ordered 1-to-N per finding | **Extract** | New `finding_evidence_steps` side-table with `step_index` (see §5) |
| **`confidence_signals_json`** | Never written from production code paths (`src/store.ts:230` writes `null`); `_updateFindingCompositeConfidence` is dead (underscore-prefixed, `src/store.ts:1403`). A stub; schema shape undefined. | None (never written) | **Drop** — coordinate with A2 (dead column) | n/a |
| `composite_confidence` | `REAL` scalar (`src/store.ts:229`); written from `upsertFinding` and set on `TriageResult` and `VerificationResult` | already scalar | **Keep as scalar** | no change |
| **`finding_metadata_json`** | `FindingMetadata`: `{ latestDynamicRunId?, dynamicRunIds?: string[], latestPatchRunId?, patchRunIds?: string[], latestDynamicStatus?, notes?: string[], blame?: {sha, author, date, summary}, introducedIn? }` (`src/types.ts:300-309`; merge logic at `src/store.ts:1561-1595`) | `blame` + `introducedIn` are stable per-finding; `latestDynamic*`/`latestPatch*` are cached aggregates; `dynamicRunIds`/`patchRunIds` duplicate the row-level FK on `dynamic_analysis_runs.fingerprint` and `patch_results.fingerprint` | **Extract (partial)** | Promote `blame_sha`, `blame_author`, `blame_date`, `blame_summary`, `introduced_in` to scalar columns on `findings`. Drop `dynamicRunIds`/`patchRunIds` — they're derivable via `SELECT … FROM dynamic_analysis_runs WHERE fingerprint = ?` (already live table). Keep `notes` as `TEXT` JSON array (rarely used, free-form). Keep `latestDynamicStatus` as a scalar column if A2 confirms it's read (check `parseDynamicAnalysisStatus` consumers). |
| `verify_poc_payload`, `verify_poc_description`, `verify_attack_vector`, `verify_preconditions` (JSON array), `verify_confidence`, `verify_exploitable`, `verify_cost_usd` | Scalar group; `verify_preconditions` is `safeJsonStringify(string[])` (`src/store.ts:1448`) | stable | **Keep as scalars; demote `verify_preconditions` to side-table** | Optional: new `finding_verify_preconditions(fingerprint, position, text)` table if A4 wants indexable search. Low priority — the array is rarely queried; can stay as JSON TEXT. |
| `poc_harness_path`, `poc_harness_language`, `poc_harness_parsed`, `poc_harness_parse_error`, `poc_harness_skipped`, `poc_harness_skip_reason`, `poc_harness_cost_usd` | Scalar group (`src/store.ts:1480-1511`) | stable | **Keep as scalars** | no change |
| `poc_run_exit_code`, `poc_run_stdout`, `poc_run_stderr`, `poc_run_verdict`, `poc_run_duration_ms` | Scalar group | stable | **Keep as scalars** | no change |

### Legitimately variable-shape (keep-as-JSON) justifications

- `triage_details_json.assumptions` / `.blindspots` / `.source_threat_ids` — these are free-text LLM outputs whose length and content vary per finding; elevating them to a side-table would produce very small rows with no query driver (no code path filters findings by `assumption LIKE ?`).
- `finding_metadata_json.notes` — free-text human/agent notes, never queried structurally.

---

## 3. `pipeline_runs.findings_json`

### Analysis

| Aspect | Evidence |
|---|---|
| Written at | `updateRunFindings()` — `src/store.ts:1139-1145`; invoked from `"run:findings-checkpoint"` bus event in store-worker (`src/bus/workers/store-worker.ts:193-199`). |
| Payload | Serialized `Finding[]` from `state.scanFindings` (pre-triage scan output). |
| Read at | Resume path `src/bus/orchestrator.ts:604-637` (used to reconstruct `state.scanFindings` without re-running scanners); baseline comparison in taint-analysis `src/agents/tasks/taint-analysis/analyze.ts:406`; SARIF report generation (tests); monorepo aggregation `src/cli/commands/monorepo-scan.ts`. |
| Overlap with `findings` table | Not a 1:1 duplicate. `findings` table rows are keyed on `fingerprint` (upserted post-triage, mutated by verification/PoC). `findings_json` is the **raw pre-triage scan output**, keyed to a specific `run_id`, including findings that were later dropped/merged. |

### Verdict

**Snapshot, not duplicate.** The contents of `findings_json` are deliberately immutable for the lifetime of the run: they freeze the scan output so a resumed run re-triages the exact same set rather than re-scanning (which could drift with `HEAD`). It cannot be reconstructed by joining `findings` against `run_id` because:

1. The `findings` table has no `run_id` column — findings are keyed by `fingerprint` and overwritten across runs on re-upsert.
2. Findings that were filtered out by `fp-filter` during the run never reach the `findings` table at all, but live in the checkpoint.
3. The JSON contains fields (`scannerConfidence`, `cwe[]`, `subcategory`, `likelihood`, `impact`) that are never persisted to the `findings` table at all.

### Recommendation

**Keep**, with two notes for Phase B:

- Document it as a run-scoped `Finding[]` checkpoint, pre-triage and
  pre-filter, rather than a canonical run artifact.
- Consider renaming to `scan_findings_json` in v100 to disambiguate from the `findings` table (cross-ref to A1 naming).

---

## 4. Split update paths

### 4a. `updateVerificationResult` + `updateVerificationCost`

**Today** (`src/store.ts:1426-1472`):

```ts
export function updateVerificationResult(db, fingerprint, result: VerificationResult): void;
export function updateVerificationCost(db, fingerprint, costUsd: number): void;
```

Caller in store-worker (`src/bus/workers/store-worker.ts:84-136`):

- `verification:result` → `updateVerificationResult` (writes 7 columns including `verify_cost_usd`).
- `verification:error` → `upsertFinding` then `updateVerificationCost` (writes only `verify_cost_usd`).

Why two functions exist today: the error path has no `VerificationResult` to write — cost is the only signal available. The result path already includes cost inside `VerificationResult.verifyCostUsd`, so `updateVerificationCost` is *never* legitimately called alongside `updateVerificationResult`.

**Proposed merge**:

```ts
// Single partial-update function
export function updateVerification(
  db: Database.Database,
  fingerprint: string,
  patch: {
    result?: VerificationResult;   // full result OR
    costOnly?: number;              // cost-only (error path)
  },
): void;
```

Internally one prepared statement with `COALESCE(?, existing)` per mutable column, runs inside a single `db.transaction(...)`. Result path passes `{ result }`; error path passes `{ costOnly: costUsd }`. Store-worker becomes:

```ts
// verification:result
updateVerification(deps.db, finding.fingerprint, { result });

// verification:error
updateVerification(deps.db, finding.fingerprint, { costOnly: costUsd });
```

### 4b. `updatePocHarnessResult` + `updatePocHarnessCost`

Same pattern (`src/store.ts:1475-1531`):

```ts
export function updatePocHarnessResult(db, fingerprint, result: PocHarnessResult): void;
export function updatePocHarnessCost(db, fingerprint, costUsd: number): void;
```

Callers: `poc-harness:result` vs `poc-harness:error` (`src/bus/workers/store-worker.ts:138-168`).

**Proposed merge**:

```ts
export function updatePocHarness(
  db: Database.Database,
  fingerprint: string,
  patch: { result?: PocHarnessResult; costOnly?: number },
): void;
```

### 4c. Other `update*Cost()` siblings

Searched for the pattern — `updateRunCost()` (`src/store.ts:1390-1400`) is distinct: it's an **incremental** `total_cost_usd += ?` on `pipeline_runs`, not a split update of a result object. Leave alone.

No other split paths found.

### Caller-change summary

| File | Line | Change |
|---|---|---|
| `src/bus/workers/store-worker.ts` | 93 | `updateVerificationResult(…, result)` → `updateVerification(…, { result })` |
| `src/bus/workers/store-worker.ts` | 135 | `updateVerificationCost(…, costUsd)` → `updateVerification(…, { costOnly: costUsd })` |
| `src/bus/workers/store-worker.ts` | 146 | `updatePocHarnessResult(…, result)` → `updatePocHarness(…, { result })` |
| `src/bus/workers/store-worker.ts` | 167 | `updatePocHarnessCost(…, costUsd)` → `updatePocHarness(…, { costOnly: costUsd })` |
| `tests/store.test.ts`, `tests/bus/orchestrator.test.ts` | various | Test imports flip to single function; assertions unchanged. |

---

## 5. ER sketches for extracted side-tables

Each side-table inserts/updates on the same event as its parent `UPDATE findings SET …` call, inside the same transaction.

### `finding_corroborations`

```
finding_corroborations
  fingerprint             TEXT  NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  signal_fingerprint      TEXT  NOT NULL   — fingerprint of the corroborating finding
  task_id                 TEXT  NOT NULL
  rule_id                 TEXT  NOT NULL
  file_path               TEXT  NOT NULL
  start_line              INTEGER NOT NULL
  score                   REAL  NOT NULL
  cwe_json                TEXT              — CWE list; small variable-shape, keep as JSON
  PRIMARY KEY (fingerprint, signal_fingerprint, task_id)
```
Lifecycle: INSERT rows whenever `upsertFinding()` runs for the parent; DELETE + re-INSERT on re-triage (simplest correct merge). CASCADE on parent delete.

### `finding_suppressions`

```
finding_suppressions
  fingerprint     TEXT  NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  rule_id         TEXT  NOT NULL   — the exclusion rule id (e.g. "custom:…", built-in)
  kind            TEXT  NOT NULL   — CHECK ('hard','soft')  (A4 dimension)
  description     TEXT  NOT NULL
  score_penalty   REAL              — NULL when kind='hard'
  PRIMARY KEY (fingerprint, rule_id)
```
Lifecycle: same as corroborations.

### `finding_taint_steps`

```
finding_taint_steps
  fingerprint   TEXT    NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  step_index    INTEGER NOT NULL   — 0-based position in the taint flow
  file_path     TEXT    NOT NULL
  line          INTEGER NOT NULL
  message       TEXT
  snippet       TEXT
  PRIMARY KEY (fingerprint, step_index)
```
Lifecycle: INSERT on upsert; DELETE old rows before bulk-INSERT new ones (order is load-bearing).

### `finding_engines`

```
finding_engines
  fingerprint   TEXT    NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  kind          TEXT    NOT NULL   — CHECK in ('semgrep','codeql','taint-analysis','agentic','dynamic')
  detail        TEXT    NOT NULL DEFAULT ''
  PRIMARY KEY (fingerprint, kind)
```
Lifecycle: UPSERT on every parent upsert; a given `(fingerprint, kind)` pair is unique.

### `finding_evidence_steps`

```
finding_evidence_steps
  fingerprint   TEXT    NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  step_index    INTEGER NOT NULL
  step_type     TEXT    NOT NULL
  description   TEXT    NOT NULL
  confidence    REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1)
  evidence      TEXT    NOT NULL
  PRIMARY KEY (fingerprint, step_index)
```
Lifecycle: written by `updateFindingCalibratedConfidence()` (`src/confidence-calibration.ts:234-240`) — today that function writes `evidence_chain_json` scalar; after extraction it does DELETE + bulk-INSERT inside a transaction.

### `finding_code_citations`

```
finding_code_citations
  fingerprint   TEXT    NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  citation_idx  INTEGER NOT NULL
  file_path     TEXT    NOT NULL
  start_line    INTEGER NOT NULL
  end_line      INTEGER NOT NULL
  snippet       TEXT    NOT NULL
  description   TEXT    NOT NULL
  PRIMARY KEY (fingerprint, citation_idx)
```
Lifecycle: DELETE + bulk-INSERT on `upsertFinding()` when `triage.codeCitations` is present.

### `finding_controls`

```
finding_controls
  fingerprint   TEXT    NOT NULL   — FK → findings.fingerprint ON DELETE CASCADE
  control_idx   INTEGER NOT NULL
  name          TEXT    NOT NULL
  description   TEXT    NOT NULL
  file_path     TEXT
  PRIMARY KEY (fingerprint, control_idx)
```
Lifecycle: same.

Note: `finding_corroborations.signal_fingerprint` intentionally does **not** have a FK to `findings.fingerprint`. Corroborating signals reference siblings that may or may not be persisted — they're raw scanner output, not all of which survive filtering. A4 should treat this as a soft reference.

---

## 6. Store-function merges proposed

In `src/store.ts`:

| Merge from | Merge to | Rationale |
|---|---|---|
| `updateVerificationResult` + `updateVerificationCost` | `updateVerification(db, fp, { result?, costOnly? })` | §4a — collapse split writes into one prepared statement. |
| `updatePocHarnessResult` + `updatePocHarnessCost` | `updatePocHarness(db, fp, { result?, costOnly? })` | §4b — same. |
| `_updateFindingCompositeConfidence` (dead, `src/store.ts:1403`) | delete entirely | §2 — `confidence_signals_json` never written; mark for drop (A2) or leave the composite score update inside `upsertFinding`. |
| `_getTotalVerificationCost`, `_getVerificationCounts`, `_parsePatchStatus`, `_getRunAssertions`, `_updatePromptHash`, `_updateRunAssertions` (all underscore-prefixed dead, `src/store.ts:660,686,1346,1759,1792,1799`) | delete | Cross-ref A2 (liveness). |
| `getStoredTriageResults` (loader that re-parses `triage_details_json`) | after §2 extraction, split into `getStoredTriageResults` (columns only) + `getStoredTriageCitations` (from `finding_code_citations`) | Extraction forces reader split but simplifies each query. |
| `parseFindingMetadata` + `updateFindingMetadata` | after promoting `blame_*` + `introduced_in` to columns, the merge logic for JSON-embedded blame disappears; the runIds mutation path drops (derivable via join) | `src/store.ts:1286-1332` + `:1561-1595`. |

In `src/store/dynamic-analysis.ts`: no merges — already uses a single INSERT OR REPLACE.

In `src/store/patch-results.ts`: `insertPatchResult` + `updatePatchResultStatus` stay separate (different event triggers).

In `src/store/crypto-behavioral.ts`: no changes.

In `src/agents/tasks/code-graph/store.ts`: `upsertGraphNode`/`upsertGraphEdge`/`upsertGraphPath` stay separate (different entity kinds with different event sources).

---

## 7. Cross-cutting observations

**For Agent 2 (liveness):** If this agent's proposal to extract a JSON column is accepted, the column is **not dead** — it becomes a new side-table. Specifically:

- `corroboration_json` → extract (NOT drop). Has active writers and readers.
- `suppression_json` → extract (NOT drop). Active.
- `taint_path_json` → extract (NOT drop). Active.
- `engine_provenance_json` → extract (NOT drop). Active.
- `evidence_chain_json` → extract (NOT drop). Active via confidence calibration.
- `triage_details_json` → partial extract (most fields become columns, side-tables, or kept as JSON). NOT drop.
- `finding_metadata_json` → partial extract (promote `blame_*`, `introduced_in`; drop `dynamicRunIds`/`patchRunIds` only because they're derivable via FK join).
- `confidence_signals_json` → **do drop**. Never written in production. Agrees with A2.

**For Agent 4 (constraints):** Every proposed side-table carries its own CHECK/NOT NULL needs. Ask A4 to specify:

- `finding_engines.kind`: CHECK IN (enum above).
- `finding_suppressions.kind`: CHECK IN ('hard','soft').
- `finding_evidence_steps.confidence`: CHECK 0..1.
- All side-tables: composite PK as listed.
- CASCADE on all `fingerprint` FKs except `finding_corroborations.signal_fingerprint` (soft reference — A4 should leave unconstrained).
- Promoted columns (`blame_sha`, `introduced_in`, etc.) inherit no new constraints unless A4 adds them.

**For Agent 1 (naming):** Proposed new table names follow `finding_<plural>` pattern:

- `finding_corroborations`, `finding_suppressions`, `finding_taint_steps`, `finding_engines`, `finding_evidence_steps`, `finding_code_citations`, `finding_controls`.

Promoted scalar columns from `finding_metadata_json` keep the TS field name converted: `blame_sha`, `blame_author`, `blame_date`, `blame_summary`, `introduced_in`. All non-JSON columns should drop the `_json` suffix per A1 convention.

Cross-ref A1 will also want to rename the `findings_json` column on `pipeline_runs` to `scan_findings_json` per §3.

---

## 8. Draft SQL

For the v100 fresh schema these `ALTER TABLE findings DROP COLUMN` statements simply **won't be in the schema** — the column never exists in v100. Only `CREATE TABLE` statements for new side-tables apply. For reference, here is the v100-shape delta.

### New side-tables (fresh schema)

```sql
CREATE TABLE finding_corroborations (
  fingerprint         TEXT    NOT NULL,
  signal_fingerprint  TEXT    NOT NULL,
  task_id             TEXT    NOT NULL,
  rule_id             TEXT    NOT NULL,
  file_path           TEXT    NOT NULL,
  start_line          INTEGER NOT NULL,
  score               REAL    NOT NULL,
  cwe_json            TEXT    NOT NULL DEFAULT '[]',
  PRIMARY KEY (fingerprint, signal_fingerprint, task_id),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);
CREATE INDEX idx_finding_corroborations_signal ON finding_corroborations(signal_fingerprint);

CREATE TABLE finding_suppressions (
  fingerprint    TEXT    NOT NULL,
  rule_id        TEXT    NOT NULL,
  kind           TEXT    NOT NULL CHECK (kind IN ('hard','soft')),
  description    TEXT    NOT NULL,
  score_penalty  REAL,
  PRIMARY KEY (fingerprint, rule_id),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);

CREATE TABLE finding_taint_steps (
  fingerprint  TEXT    NOT NULL,
  step_index   INTEGER NOT NULL,
  file_path    TEXT    NOT NULL,
  line         INTEGER NOT NULL,
  message      TEXT,
  snippet      TEXT,
  PRIMARY KEY (fingerprint, step_index),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);

CREATE TABLE finding_engines (
  fingerprint  TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('semgrep','codeql','taint-analysis','agentic','dynamic')),
  detail       TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (fingerprint, kind),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);

CREATE TABLE finding_evidence_steps (
  fingerprint  TEXT    NOT NULL,
  step_index   INTEGER NOT NULL,
  step_type    TEXT    NOT NULL,
  description  TEXT    NOT NULL,
  confidence   REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  evidence     TEXT    NOT NULL,
  PRIMARY KEY (fingerprint, step_index),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);

CREATE TABLE finding_code_citations (
  fingerprint   TEXT    NOT NULL,
  citation_idx  INTEGER NOT NULL,
  file_path     TEXT    NOT NULL,
  start_line    INTEGER NOT NULL,
  end_line      INTEGER NOT NULL,
  snippet       TEXT    NOT NULL,
  description   TEXT    NOT NULL,
  PRIMARY KEY (fingerprint, citation_idx),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);

CREATE TABLE finding_controls (
  fingerprint   TEXT    NOT NULL,
  control_idx   INTEGER NOT NULL,
  name          TEXT    NOT NULL,
  description   TEXT    NOT NULL,
  file_path     TEXT,
  PRIMARY KEY (fingerprint, control_idx),
  FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint) ON DELETE CASCADE
);
```

### Columns promoted out of JSON blobs onto `findings` (v100 partial)

Add to `findings` in v100:

```sql
-- from triage_details_json
title                   TEXT,
attack_narrative        TEXT,
display_severity        TEXT    CHECK (display_severity IS NULL OR display_severity IN ('critical','high','medium','low')),
is_vulnerable           INTEGER,                            -- 0/1/NULL
exploit_scenario        TEXT,
recommended_fix         TEXT,
rule_refinement_hint    TEXT,
triage_schema_version   TEXT,
source_why              TEXT,
source_evidence         TEXT,
source_is_fp            INTEGER,
sink_why                TEXT,
sink_evidence           TEXT,
sink_is_fp              INTEGER,
assumptions_json        TEXT,                               -- free-text arrays stay as JSON
blindspots_json         TEXT,
source_threat_ids_json  TEXT,

-- from finding_metadata_json (blame promotion)
blame_sha               TEXT,
blame_author            TEXT,
blame_date              TEXT,
blame_summary           TEXT,
introduced_in           TEXT,
latest_dynamic_status   TEXT    CHECK (latest_dynamic_status IS NULL OR latest_dynamic_status IN ('confirmed','interesting','rejected','error')),
notes_json              TEXT,                               -- free-text, rare
```

### Columns NOT in v100 `findings` (extracted-out or dropped)

| Column | Reason |
|---|---|
| `triage_details_json` | Fields promoted to columns + `finding_code_citations`, `finding_controls` tables |
| `corroboration_json` | → `finding_corroborations` |
| `suppression_json` | → `finding_suppressions` |
| `taint_path_json` | → `finding_taint_steps` |
| `engine_provenance_json` | → `finding_engines` |
| `evidence_chain_json` | → `finding_evidence_steps` |
| `confidence_signals_json` | Dead — never written. Drop. |
| `finding_metadata_json` | Partial promotion + derivable fields dropped |
| `adjusted_score` | **Kept** (nullable) — see §1. Read upsert change: only write when `finding.adjustedScore !== undefined`, not `?? score`. |

### Reference: what a post-reset `findings` upsert transaction looks like

```sql
BEGIN;
  INSERT INTO findings (fingerprint, repo, ref, rule_id, …, adjusted_score, title, attack_narrative, …, blame_sha, blame_author, …)
    VALUES (?, ?, ?, ?, …)
    ON CONFLICT(fingerprint) DO UPDATE SET … ;
  DELETE FROM finding_taint_steps WHERE fingerprint = ?;
  INSERT INTO finding_taint_steps (fingerprint, step_index, …) VALUES (?,0,…),(?,1,…) …;
  DELETE FROM finding_engines WHERE fingerprint = ?;
  INSERT INTO finding_engines (fingerprint, kind, detail) VALUES (?, 'semgrep', …), (?, 'codeql', …);
  -- same pattern for corroborations / suppressions / evidence_steps / code_citations / controls
COMMIT;
```

This becomes a single `db.transaction(() => { … })()` call in the refactored `upsertFinding()`.

### Reference: merged update signatures (§4)

```ts
export function updateVerification(
  db: Database.Database,
  fingerprint: string,
  patch: { result?: VerificationResult; costOnly?: number },
): void {
  const tx = db.transaction(() => {
    if (patch.result) {
      db.prepare(`
        UPDATE findings
        SET verify_exploitable = ?, verify_poc_payload = ?, verify_poc_description = ?,
            verify_attack_vector = ?, verify_preconditions = ?, verify_confidence = ?,
            verify_cost_usd = ?, updated_at = datetime('now')
        WHERE fingerprint = ?
      `).run(
        patch.result.exploitable ? 1 : 0,
        patch.result.pocPayload, patch.result.pocDescription, patch.result.attackVector,
        safeJsonStringify(patch.result.preconditions),
        patch.result.confidence, patch.result.verifyCostUsd ?? null,
        fingerprint,
      );
    } else if (typeof patch.costOnly === "number" && patch.costOnly >= 0) {
      db.prepare(`
        UPDATE findings SET verify_cost_usd = ?, updated_at = datetime('now')
        WHERE fingerprint = ?
      `).run(patch.costOnly, fingerprint);
    }
  });
  tx();
}
// updatePocHarness: same pattern, different column list.
```

---

## Verification checklist (self-check)

- [x] Every JSON column has a triage decision with evidence (table in §2).
- [x] Every proposed new side-table has name, column list, parent FK, insertion lifecycle (§5 + §8).
- [x] Split update paths before/after with function signatures (§4).
- [x] adjustedScore read/write census + recommendation (§1).
- [x] findings_json snapshot-vs-duplicate analysis (§3).
- [x] Store-function merges listed (§6).
- [x] Cross-cutting flags for A1/A2/A4 (§7).
- [x] Draft SQL for extracted side-tables (§8).
