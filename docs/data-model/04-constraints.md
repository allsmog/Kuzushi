# Agent 4 — Constraints & Integrity (DB-level)

Dimension owned: **CHECK, NOT NULL, UNIQUE, FK, PRAGMA** for the v100 fresh
schema. Concept-level only — the table identity and column names may shift
after A5 (structural) and A1 (naming) resolve. Where the concept name is
stable, canonical names are used; otherwise "(column conceptually equivalent
to X)" phrasing is used.

Scope notes:

- A2 may drop columns that this doc constrains. Where that happens, the
  constraint simply disappears with the column (no conflict).
- A5 may extract JSON blobs or merge tables. When a constraint would be
  cleaner post-extraction, it is flagged in `## Cross-cutting observations`.
- All evidence cites `path/file.ts:line` so the main thread can verify.

---

## 1. Current state audit

### 1a. PRAGMA state (observed in `src/store.ts:119–136`)

| PRAGMA | Current | Proposed |
|---|---|---|
| `journal_mode` | `WAL` | `WAL` (keep) |
| `synchronous` | `NORMAL` | `NORMAL` (keep) |
| `busy_timeout` | `5000` ms | `5000` ms (keep) |
| `wal_checkpoint(TRUNCATE)` | run once at init | keep |
| **`foreign_keys`** | **NOT SET** (SQLite default = OFF) | **`ON`** |

Evidence that FKs are not enforced today:
- `initDb()` at `src/store.ts:119–136` sets only `journal_mode`,
  `busy_timeout`, `synchronous`. No `foreign_keys` pragma.
- Existing FK-shaped references in schema (`code_graph_edges.from_node_id
  REFERENCES code_graph_nodes(node_id)`, migrations/019; `workspace_snapshots.
  workspace_id REFERENCES workspaces(id) ON DELETE CASCADE`, migrations/025)
  are therefore decorative only — SQLite parses and ignores them at write
  time.

### 1b. Per-table summary (declared vs app-enforced)

Legend: *App-E* = column is always written non-null by app (grep-verified);
*App-W* = written but may be null; *App-O* = optional / app guards null.

#### `findings` (src/migrations/001 + 002, 003–007, 010, 012, 013, 016, 017, 024)

- **PK:** `fingerprint` (TEXT). App always supplies via
  `computeFingerprint(repo, ref, taskId, rule, file, line)` — deterministic.
  See `src/scanners/normalize-findings.ts:170–185`.
- **CHECK `verdict IN ('tp','fp','needs_review')`** — STALE. App type
  `Verdict = 'tp'|'fp'|'needs_review'|'by_design'` (`src/types.ts:87`); app
  writes `'by_design'` via `updateFindingVerdict()` at
  `src/store.ts:1036,1039` and via `design-decision-classifier.ts:211`.
  This is a live bug: calling `updateFindingVerdict(…, 'by_design')` raises
  a SQLite CHECK constraint error. Agent-4 fix: expand CHECK to include
  `'by_design'`.
- **CHECK `confidence >= 0 AND confidence <= 1`** — OK; matches
  `FindingSchema` (`src/schemas.ts`) z.number 0..1 semantics (Zod does not
  enforce the bound but scoring pipeline does).
- **NOT NULL** currently on: `repo, ref, rule_id, file_path, start_line,
  severity, message, verdict, confidence, rationale, verification_steps,
  created_at, updated_at, task_id` (task_id defaults `'semgrep'`, migration
  002 line 10). App-E for all of these (scan worker always populates).
- **No composite UNIQUE** beyond PK. Because `fingerprint` is
  `sha256(repo|ref|taskId|rule|file|line)` it is already globally unique
  across `(repo, ref)` — so the practical integrity value of a composite
  `UNIQUE(repo, ref, fingerprint)` is low (a hash collision would already
  bypass it). Keep PK on fingerprint.
- **No FK** — fingerprint is an island; four other tables point at it
  (dynamic_analysis_runs, patch_results, crypto_behavioral_runs,
  finding_assertions, trajectories) but without FKs those references can
  dangle after `deleteFindingsByFingerprints()` (`src/store.ts:1062`).

#### `pipeline_runs` (001 + 008, 009, 014, 015, 021, 023)

- **PK:** `run_id` (TEXT).
- **CHECK `status IN ('scanning','triaging','verifying','poc-harnessing',
  'dynamic-analyzing','complete','error','aborted')`** — matches observed
  writers. Migration 023 added `'aborted'` + `'dynamic-analyzing'`.
- **TS divergence:** `PipelineRunStatus` at `src/store.ts:32–39` is missing
  `'aborted'`. The app writes `'aborted'` via a raw SQL UPDATE at
  `src/store.ts:1813` (`SET status = 'aborted'`). This is a TS-vs-DB drift
  Agent 1 should address when consolidating types; the CHECK is correct.
- **NOT NULL** currently on: `repo, started_at, status, config_json,
  scan_opts_json`. App-E for all (see `src/store.ts:1084–1095`
  `INSERT INTO pipeline_runs (…) VALUES (?, ?, ?, 'scanning', ?, ?)`).
- `findings_json, context_json, completed_at, metrics_json, assertions_json,
  prompt_hash, head_ref` all nullable — correct (populated lazily across
  the pipeline).
- **No FK.** None needed — run_id is the root of the hierarchy.

#### `dynamic_analysis_runs` (017)

- **PK:** `dynamic_run_id`.
- **CHECK `status IN ('confirmed','interesting','rejected','error')`** —
  matches `DynamicAnalysisStatus` (`src/types.ts:239`) and Zod schema
  (`src/schemas.ts:45–50`).
- **NO CHECK on `execution_verdict`** — app-side it is `PocExecVerdict =
  'PASS'|'FAIL'|'ERROR'|'TIMEOUT'` (`src/schemas.ts:29`). Silent divergence
  risk.
- **NOT NULL** on: `fingerprint, repo, status, score, proof_value,
  iterations, created_at, updated_at`. App-E; see
  `src/store/dynamic-analysis.ts:31–65`.
- **No FK** on `fingerprint` or `pipeline_run_id` despite being obvious
  references. Insert path does not validate; fingerprint could be stale
  after findings delete.

#### `patch_results` (017 + 020)

- **PK:** `patch_run_id`.
- **CHECK `status IN ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE',
  'TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')`** — matches
  `PatchStatus` (`src/types.ts:269–276`) after migration 020.
- **NOT NULL** on: `fingerprint, repo, status, iterations, history_json,
  created_at, updated_at`. App-E (`src/store/patch-results.ts:22–43`).
- **No FK** on `fingerprint`.

#### `crypto_behavioral_runs` (018)

- **PK:** `run_id`.
- **NO CHECK on `test_type`** — should be `CryptoBehavioralTestType =
  'timing'|'ecb-mode'|'weak-hash'|'weak-prng'|'key-length'|'edge-case'`
  (`src/crypto-behavioral/types.ts:1–7`).
- **NO CHECK on `verdict`** — should be `CryptoBehavioralVerdict =
  'vulnerable'|'secure'|'inconclusive'|'error'` (`src/crypto-behavioral/
  types.ts:9`).
- **NO CHECK on `execution_verdict`** — should be `PocExecVerdict`.
- **NOT NULL** on: `fingerprint, repo, test_type, verdict, created_at,
  updated_at`. App-E (`src/store/crypto-behavioral.ts:34–71`).
- **No FK** on `fingerprint` or `pipeline_run_id`.

#### `finding_assertions` (015)

- **PK:** `id` (AUTOINCREMENT).
- **NOT NULL** on: `run_id, fingerprint, assertion_name, passed, score,
  weight, reason, created_at`. App-E (`src/store.ts:1746–1755`).
- **No FK** on `fingerprint` or `run_id`. The `run_id` always comes from
  an active pipeline_runs row (assertions are written inside the same
  transaction flow) — so FK with `ON DELETE CASCADE` is safe and beneficial.

#### `trajectories` (011)

- **PK:** `id`.
- **NOT NULL** on: `rule_id, cwes_json, task_id, verdict, confidence,
  steps_json, summary, repo, created_at, updated_at`. Fingerprint is
  explicitly nullable (`trajectory-memory.ts:158` passes `string | null`).
- **`was_correct` nullable** (tri-state: null=unverified, 0=wrong, 1=right).
  Correct design.
- **NO CHECK on `verdict`** — should match `Verdict` union
  (`'tp'|'fp'|'needs_review'|'by_design'`).
- **No FK** on `fingerprint`. Because fingerprint is nullable, the FK
  must be `ON DELETE SET NULL`.

#### `calibration_weights` (010)

- **Composite PK:** `(step_type, rule_family)` — matches app's UPSERT
  pattern (`src/confidence-calibration.ts:173`).
- **NOT NULL** on all columns. App-E.
- No enum/CHECK needed; step_type and rule_family are open strings.
- Confirmed: composite PK is correct; no extra UNIQUE needed.

#### `code_graph_nodes` (019)

- **PK:** `node_id` (TEXT, deterministic hash of
  `repo|filePath|startLine|symbol`, `code-graph/store.ts:13–21`).
- **NOT NULL** on: `repo, run_id, file_path, start_line, node_kind,
  confidence, source, created_at, updated_at`.
- **NO CHECK on `node_kind`** — should be `CodeGraphNodeKind` (14 values,
  `src/agents/tasks/code-graph/types.ts:2–16`).
- **NO CHECK on `source`** — should be `GraphSource = 'static'|'llm'|
  'hybrid'` (`src/agents/tasks/code-graph/types.ts:34`).

#### `code_graph_edges` (019)

- **PK:** `edge_id`.
- **FK (declared, unenforced): `from_node_id REFERENCES
  code_graph_nodes(node_id)`, `to_node_id REFERENCES
  code_graph_nodes(node_id)`**. Upgrade to enforced once PRAGMA is ON.
- **NO CHECK on `edge_kind`** — should be `CodeGraphEdgeKind` (12 values,
  `src/agents/tasks/code-graph/types.ts:19–31`).
- **NO CHECK on `source`** — as above.
- `invalidateStaleNodes()` (`code-graph/store.ts:200–236`) already deletes
  edges before nodes, so `ON DELETE CASCADE` is safe and would let us
  simplify that function.

#### `code_graph_paths` (019)

- **PK:** `path_id`.
- **FK (declared, unenforced): `entry_node_id`, `target_node_id` both
  REFERENCE `code_graph_nodes(node_id)`**.
- No enum columns.
- `has_sanitizer INTEGER` — treated as boolean. Should be `CHECK
  has_sanitizer IN (0, 1)`.

#### `workspaces` / `workspace_snapshots` (025)

- `workspaces.name UNIQUE` — correct; app enforces via name-based lookup
  (`src/workspace/manager.ts:15`).
- `workspace_snapshots.workspace_id REFERENCES workspaces(id) ON DELETE
  CASCADE` — declared correctly; will activate when FKs are ON.

#### `schema_version`

- Governance-only table. No constraints beyond PK on `version`. No
  changes.

#### `intel_documents`, `intel_fts` (ad-hoc in `src/intel/store.ts:21`)

- **Out of scope for Agent 4's constraint work** beyond confirming that
  moving these tables into migration 100 (A3's scope) is a precondition for
  our v100 schema to be self-contained. No CHECKs or FKs proposed here.

---

## 2. Constraint matrix

Columns reference canonical names; if A1/A5 rename, the constraint moves
with the column.

| Table | Column | Constraint | Current | Proposed | Rationale | Evidence |
|---|---|---|---|---|---|---|
| findings | verdict | CHECK | `IN ('tp','fp','needs_review')` | `IN ('tp','fp','needs_review','by_design')` | Stale CHECK blocks legal updates | src/migrations/001:22; src/types.ts:87; src/store.ts:1036,1039 |
| findings | confidence | CHECK | `>= 0 AND <= 1` | keep | Matches domain | src/migrations/001:23 |
| findings | fingerprint | PK | PK | keep | Globally unique hash | src/scanners/normalize-findings.ts:170 |
| findings | task_id | NOT NULL DEFAULT 'semgrep' | same | NOT NULL (drop default) | Scanner always supplies; default was for legacy back-compat of migration 002 | src/migrations/002:10 |
| findings | proof_state | CHECK | none | `IN ('symbolic_only','inconclusive','execution_attempted','execution_rejected','execution_confirmed')` | ProofState union | src/scanners/types.ts:32-37 |
| findings | poc_run_verdict | CHECK | none | `IN ('PASS','FAIL','ERROR','TIMEOUT')` | PocExecVerdict | src/schemas.ts:29 |
| findings | verify_exploitable | CHECK | none | `IN (0,1)` or NULL | Boolean-as-int | src/migrations/005:12 |
| findings | poc_harness_parsed | CHECK | none | `IN (0,1)` or NULL | Boolean-as-int | src/migrations/006:14 |
| findings | poc_harness_skipped | CHECK | none | `IN (0,1)` or NULL | Boolean-as-int | src/migrations/006:16 |
| findings | severity | CHECK | none | **defer to A1** — if a `Severity` enum is chosen, CHECK there; currently open string written from CodeQL/Semgrep normalizers | — | src/scanners/run-codeql.ts:733; src/scanners/normalize-findings.ts:238 |
| pipeline_runs | status | CHECK | 8 values | keep + align TS | DB already correct | src/migrations/023:34 |
| pipeline_runs | total_cost_usd | NOT NULL DEFAULT 0 | same | keep | App always has 0+ | src/migrations/001:42 |
| dynamic_analysis_runs | status | CHECK | `IN ('confirmed','interesting','rejected','error')` | keep | Matches DynamicAnalysisStatus | src/types.ts:239 |
| dynamic_analysis_runs | execution_verdict | CHECK | none | `IN ('PASS','FAIL','ERROR','TIMEOUT')` nullable | PocExecVerdict union | src/schemas.ts:29; src/types.ts:260 |
| dynamic_analysis_runs | coverage_mode | CHECK | none | `IN ('none','node-v8','python-coverage')` nullable | DynamicCoverageMode | src/types.ts:241 |
| dynamic_analysis_runs | fingerprint | FK | none | `REFERENCES findings(fingerprint) ON DELETE CASCADE` | Dangling refs after delete | src/store/dynamic-analysis.ts:44 |
| dynamic_analysis_runs | pipeline_run_id | FK | none | `REFERENCES pipeline_runs(run_id) ON DELETE SET NULL` | Keep history if run deleted | src/store/dynamic-analysis.ts:43 |
| patch_results | status | CHECK | 7 values | keep | Matches PatchStatus | src/migrations/020:19 |
| patch_results | fingerprint | FK | none | `REFERENCES findings(fingerprint) ON DELETE CASCADE` | Dangling refs | src/store/patch-results.ts:31 |
| crypto_behavioral_runs | test_type | CHECK | none | `IN ('timing','ecb-mode','weak-hash','weak-prng','key-length','edge-case')` | CryptoBehavioralTestType | src/crypto-behavioral/types.ts:1-7 |
| crypto_behavioral_runs | verdict | CHECK | none | `IN ('vulnerable','secure','inconclusive','error')` | CryptoBehavioralVerdict | src/crypto-behavioral/types.ts:9 |
| crypto_behavioral_runs | execution_verdict | CHECK | none | `IN ('PASS','FAIL','ERROR','TIMEOUT')` nullable | PocExecVerdict | src/crypto-behavioral/types.ts:11 |
| crypto_behavioral_runs | fingerprint | FK | none | `REFERENCES findings(fingerprint) ON DELETE CASCADE` | Dangling refs | src/store/crypto-behavioral.ts:47 |
| crypto_behavioral_runs | pipeline_run_id | FK | none | `REFERENCES pipeline_runs(run_id) ON DELETE SET NULL` | Preserve crypto run history | src/store/crypto-behavioral.ts:46 |
| finding_assertions | fingerprint | FK | none | `REFERENCES findings(fingerprint) ON DELETE CASCADE` | Dangling refs | src/store.ts:1747 |
| finding_assertions | run_id | FK | none | `REFERENCES pipeline_runs(run_id) ON DELETE CASCADE` | Assertion is a subordinate of the run | src/store.ts:1747 |
| finding_assertions | passed | CHECK | none | `IN (0,1)` | Boolean-as-int | src/store.ts:1752 |
| trajectories | verdict | CHECK | none | `IN ('tp','fp','needs_review','by_design')` | Verdict union | src/types.ts:87 |
| trajectories | was_correct | CHECK | none | `IN (0,1)` OR NULL | Tri-state boolean | src/trajectory-memory.ts:168 |
| trajectories | fingerprint | FK | none | `REFERENCES findings(fingerprint) ON DELETE SET NULL` | Column is nullable; keep historic trajectories after repo wipe | src/trajectory-memory.ts:158 |
| calibration_weights | (step_type, rule_family) | PK | composite PK | keep | Confirmed correct | src/migrations/010:15 |
| code_graph_nodes | node_kind | CHECK | none | enum of 14 kinds (see §3) | CodeGraphNodeKind | src/agents/tasks/code-graph/types.ts:2 |
| code_graph_nodes | source | CHECK | none | `IN ('static','llm','hybrid')` | GraphSource | src/agents/tasks/code-graph/types.ts:34 |
| code_graph_edges | edge_kind | CHECK | none | enum of 12 kinds (see §3) | CodeGraphEdgeKind | src/agents/tasks/code-graph/types.ts:19 |
| code_graph_edges | source | CHECK | none | `IN ('static','llm','hybrid')` | GraphSource | src/agents/tasks/code-graph/types.ts:34 |
| code_graph_edges | from_node_id | FK | declared, unenforced | `REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE` (once PRAGMA on) | Enforce edge integrity | src/migrations/019:35 |
| code_graph_edges | to_node_id | FK | declared, unenforced | `REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE` | Enforce edge integrity | src/migrations/019:35 |
| code_graph_paths | entry_node_id | FK | declared, unenforced | `REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE` | Enforce path integrity | src/migrations/019:56 |
| code_graph_paths | target_node_id | FK | declared, unenforced | `REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE` | Enforce path integrity | src/migrations/019:57 |
| code_graph_paths | has_sanitizer | CHECK | none | `IN (0,1)` | Boolean-as-int | src/agents/tasks/code-graph/store.ts:117 |
| workspaces | name | UNIQUE | UNIQUE | keep | Name-based lookup | src/workspace/manager.ts:15 |
| workspace_snapshots | workspace_id | FK | declared, unenforced | enforce same (`ON DELETE CASCADE`) | Cascade cleanup | src/migrations/025:26 |

---

## 3. Enum value sources of truth

For every enum-like TEXT column, we list (1) the current DB CHECK values,
(2) the TS union (source of truth), (3) values actually emitted by
inspected code paths, and (4) the verdict.

### findings.verdict

| Source | Values |
|---|---|
| Current DB CHECK | `tp`, `fp`, `needs_review` |
| TS union (`src/types.ts:87`) | `tp`, `fp`, `needs_review`, `by_design` |
| Zod (`src/schemas.ts:14`) | `tp`, `fp`, `needs_review`, `by_design` |
| Observed writes | `tp` (triage), `fp` (triage), `needs_review` (fallback), `by_design` (design-decision-classifier.ts:211, updateFindingVerdict at store.ts:1039) |
| **Proposed v100** | `tp`, `fp`, `needs_review`, `by_design` |
| **Verdict** | **DIVERGE — fix by expanding CHECK.** Already causes runtime CHECK failures. |

### pipeline_runs.status

| Source | Values |
|---|---|
| Current DB CHECK | `scanning`, `triaging`, `verifying`, `poc-harnessing`, `dynamic-analyzing`, `complete`, `error`, `aborted` |
| TS union (`src/store.ts:32–39`) | `scanning`, `triaging`, `verifying`, `poc-harnessing`, `dynamic-analyzing`, `complete`, `error` *(missing 'aborted')* |
| Observed writes | all 8 CHECK values used (aborted via raw SQL at `src/store.ts:1813`) |
| **Proposed v100** | `scanning`, `triaging`, `verifying`, `poc-harnessing`, `dynamic-analyzing`, `complete`, `error`, `aborted` |
| **Verdict** | DB CHECK correct. TS type is missing `'aborted'` — A1 should fix when consolidating types. |

### dynamic_analysis_runs.status

| Source | Values |
|---|---|
| Current DB CHECK | `confirmed`, `interesting`, `rejected`, `error` |
| TS union (`src/types.ts:239`) | `confirmed`, `interesting`, `rejected`, `error` |
| Zod (`src/schemas.ts:45–50`) | same |
| Observed writes | `src/store/dynamic-analysis.ts:128–137` allows same 4 |
| **Proposed v100** | unchanged |
| **Verdict** | OK. |

### dynamic_analysis_runs.execution_verdict

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/types.ts:260`) | `PASS`, `FAIL`, `ERROR`, `TIMEOUT` |
| Zod `PocExecVerdictSchema` (`src/schemas.ts:29`) | same |
| **Proposed v100** | `CHECK (execution_verdict IS NULL OR execution_verdict IN ('PASS','FAIL','ERROR','TIMEOUT'))` |
| **Verdict** | GAP — add CHECK. |

### dynamic_analysis_runs.coverage_mode

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union | `none`, `node-v8`, `python-coverage` (`src/types.ts:241`) |
| **Proposed v100** | `CHECK (coverage_mode IS NULL OR coverage_mode IN ('none','node-v8','python-coverage'))` |
| **Verdict** | GAP — add CHECK. |

### patch_results.status

| Source | Values |
|---|---|
| Current DB CHECK | `APPLY_FAILED`, `BUILD_FAILED`, `STILL_VULNERABLE`, `TESTS_FAILED`, `SOUND`, `VERIFIED`, `UNKNOWN` |
| TS `PatchStatus` (`src/types.ts:269–276`) | same 7 |
| Zod (`src/schemas.ts:52–60`) | same 7 |
| Observed writes | all 7 via `src/store/patch-results.ts:34` + `updatePatchResultStatus` |
| **Verdict** | OK (migration 020 already aligned). |

### crypto_behavioral_runs.test_type

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/crypto-behavioral/types.ts:1–7`) | `timing`, `ecb-mode`, `weak-hash`, `weak-prng`, `key-length`, `edge-case` |
| **Proposed v100** | `CHECK (test_type IN ('timing','ecb-mode','weak-hash','weak-prng','key-length','edge-case'))` |
| **Verdict** | GAP — add CHECK. |

### crypto_behavioral_runs.verdict

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/crypto-behavioral/types.ts:9`) | `vulnerable`, `secure`, `inconclusive`, `error` |
| **Proposed v100** | `CHECK (verdict IN ('vulnerable','secure','inconclusive','error'))` |
| **Verdict** | GAP — add CHECK. |

### crypto_behavioral_runs.execution_verdict

Same set as dynamic_analysis_runs.execution_verdict — `PASS|FAIL|ERROR|
TIMEOUT`. GAP — add matching CHECK.

### findings.poc_run_verdict

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| Zod (`src/schemas.ts:838`) | PocExecVerdict nullable |
| **Proposed v100** | `CHECK (poc_run_verdict IS NULL OR poc_run_verdict IN ('PASS','FAIL','ERROR','TIMEOUT'))` |
| **Verdict** | GAP. |

### findings.proof_state

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/scanners/types.ts:32–37`) | `symbolic_only`, `execution_attempted`, `execution_confirmed`, `execution_rejected`, `inconclusive` |
| Runtime parser (`src/store.ts:1238`) | same 5 + NULL |
| **Proposed v100** | `CHECK (proof_state IS NULL OR proof_state IN ('symbolic_only','inconclusive','execution_attempted','execution_rejected','execution_confirmed'))` |
| **Verdict** | GAP. |

### trajectories.verdict

Same set as findings.verdict — `tp|fp|needs_review|by_design`. GAP.

### code_graph_nodes.node_kind

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/agents/tasks/code-graph/types.ts:2–16`) | `entry-http`, `entry-cli`, `entry-event`, `entry-cron`, `entry-background`, `middleware`, `controller`, `service`, `data-access`, `external-call`, `sanitizer`, `validator`, `transformer`, `unknown` |
| Observed reads use `LIKE 'entry-%'` query (`code-graph/store.ts:140`) | depends on the 5 entry-* kinds |
| **Proposed v100** | CHECK with all 14 values |
| **Verdict** | GAP. |

### code_graph_nodes.source & code_graph_edges.source

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/agents/tasks/code-graph/types.ts:34`) | `static`, `llm`, `hybrid` |
| **Proposed v100** | `CHECK (source IN ('static','llm','hybrid'))` |
| **Verdict** | GAP. |

### code_graph_edges.edge_kind

| Source | Values |
|---|---|
| Current DB CHECK | *(none)* |
| TS union (`src/agents/tasks/code-graph/types.ts:19–31`) | `calls`, `imports`, `middleware-chain`, `callback`, `promise-chain`, `event-emit`, `event-listen`, `di-inject`, `dynamic-dispatch`, `data-flow`, `config-read`, `serialization` |
| **Proposed v100** | CHECK with all 12 values |
| **Verdict** | GAP. |

### Booleans-as-INTEGER columns

The codebase stores booleans as `INTEGER` (SQLite idiom). Proposed uniform
CHECK: `col IN (0, 1)` (optionally `IS NULL` if nullable).

| Column | Nullable? |
|---|---|
| findings.verify_exploitable | yes |
| findings.poc_harness_parsed | yes |
| findings.poc_harness_skipped | yes |
| finding_assertions.passed | no |
| trajectories.was_correct | yes (tri-state) |
| code_graph_paths.has_sanitizer | no (default 0) |

---

## 4. FK plan

Every FK explicitly specifies `ON DELETE` behavior. Policy per relationship:

- **CASCADE** where the child row's meaning is tied to the parent and
  cleanup is desired (deleting the parent should remove dependent rows).
- **SET NULL** where the child row has independent historical value
  (trajectories survive repo wipe; crypto/dynamic runs survive pipeline-run
  deletion).
- **RESTRICT** is never used — the codebase has no explicit "keep parent
  if children exist" pattern.

| Child table.column | Parent table.column | ON DELETE | Rationale |
|---|---|---|---|
| dynamic_analysis_runs.fingerprint | findings.fingerprint | **CASCADE** | A finding wiped via `deleteFindingsByFingerprints` should not leave orphan dynamic runs. Reports already aggregate dynamic runs under a finding (`src/store/dynamic-analysis.ts:80–93`). |
| dynamic_analysis_runs.pipeline_run_id | pipeline_runs.run_id | **SET NULL** | Pipeline runs may be pruned for retention; dynamic runs retain analytic value without the containing pipeline row. |
| patch_results.fingerprint | findings.fingerprint | **CASCADE** | Patch history is per-finding; orphan patches have no consumer. |
| crypto_behavioral_runs.fingerprint | findings.fingerprint | **CASCADE** | Same rationale as dynamic_analysis_runs. |
| crypto_behavioral_runs.pipeline_run_id | pipeline_runs.run_id | **SET NULL** | Preserve timing-test history. |
| finding_assertions.fingerprint | findings.fingerprint | **CASCADE** | Assertions are per-finding verifications; orphans have no meaning. |
| finding_assertions.run_id | pipeline_runs.run_id | **CASCADE** | Assertions are produced inside a run; if the run is deleted, assertions should go too (same lifecycle as `pipeline_runs.assertions_json`). |
| trajectories.fingerprint | findings.fingerprint | **SET NULL** | Trajectories are cross-run learning artifacts; they must survive repo-wipe (column is already nullable). |
| code_graph_edges.from_node_id | code_graph_nodes.node_id | **CASCADE** | `invalidateStaleNodes()` already deletes edges before nodes (`code-graph/store.ts:215–227`); CASCADE simplifies that function. |
| code_graph_edges.to_node_id | code_graph_nodes.node_id | **CASCADE** | same |
| code_graph_paths.entry_node_id | code_graph_nodes.node_id | **CASCADE** | paths are derived artifacts |
| code_graph_paths.target_node_id | code_graph_nodes.node_id | **CASCADE** | same |
| workspace_snapshots.workspace_id | workspaces.id | **CASCADE** | already declared (migration 025); just needs PRAGMA on. |

**Caveat:** turning on `PRAGMA foreign_keys = ON` will surface any existing
dangling references on v100 migration. Since v100 is a fresh reset (A3's
scope), existing dangling references in `.bak` databases are not migrated
forward — clean slate, no compatibility burden.

---

## 5. PRAGMA recommendations

| PRAGMA | Current (initDb) | Proposed | Notes |
|---|---|---|---|
| `journal_mode` | `WAL` | `WAL` | Keep. Needed for concurrent-reader performance. |
| `synchronous` | `NORMAL` | `NORMAL` | Keep. Comment at `src/store.ts:123–126` justifies. |
| `busy_timeout` | `5000` | `5000` | Keep. |
| `foreign_keys` | **unset (OFF)** | **`ON`** | Required for all FKs above. Must be set per-connection. Place in `initDb()` *before* `runMigrations(db, allMigrations)` so migration 100's FK-bearing tables are created in an FK-enforced session. Existing migrations 001–025 are untouched (running against a fresh v100 DB means they do not run — A3's reset branch). |
| `wal_checkpoint(TRUNCATE)` | called | keep | No impact on integrity. |
| `cache_size` | unset (default) | consider `-20000` (20 MiB, negative = KiB) — optional tuning | Not integrity-related. Flag-only. |

### Placement

Recommended ordering in `initDb()` after v100 reset support lands:

```ts
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");
db.pragma("synchronous = NORMAL");
db.pragma("foreign_keys = ON");         // NEW — must be before migrations
runMigrations(db, allMigrations);
db.pragma("wal_checkpoint(TRUNCATE)");
return db;
```

---

## 6. Cross-cutting observations

Flags for other agents. Not resolved here.

- **@A5 — JSON blob CHECKs:** Several JSON columns (`triage_details_json`,
  `engine_provenance_json`, `evidence_chain_json`, `taint_path_json`,
  `corroboration_json`, `confidence_signals_json`) have no shape
  constraint today. If A5 extracts any of these into relational rows, the
  CHECKs proposed above for `proof_state`, `poc_run_verdict` move with
  the column. If A5 keeps them JSON, a `CHECK(json_valid(col))` is
  cheap and catches parse errors at write time.
- **@A5 — `pipeline_runs.findings_json` snapshot:** If A5 removes this
  (since findings are already in `findings` table), no constraint work on
  this column is needed.
- **@A1 — severity enum:** No TS union exists for severity today — it's an
  open string from Semgrep/CodeQL normalizers. If A1 introduces a
  canonical `Severity` enum, add `CHECK (severity IN (...))` to findings.
- **@A1 — PipelineRunStatus missing `'aborted'`:** the TS union at
  `src/store.ts:32–39` needs `'aborted'` added. A1 owns the type edit; the
  DB CHECK is already correct.
- **@A2 — dead columns:** If A2 drops `adjusted_score`, the constraint-
  matrix row for it disappears with it. Same applies to anything in the
  12 JSON columns list.
- **@A3 — PRAGMA position:** `PRAGMA foreign_keys = ON` must be set at the
  top of `initDb()` — note in the migration style guide. Without this,
  the FKs declared in migration 100 are decorative, exactly repeating the
  current migration-019/025 mistake.
- **@A3 — intel tables:** `intel_documents` is created ad-hoc in
  `src/intel/store.ts:21` and is not in `generated/db/schema.sql`. When A3
  folds it into migration 100, no CHECKs or FKs are proposed by Agent 4.
- **@A5 — dynamic_analysis_runs ↔ findings fingerprint:** If A5 normalizes
  dynamic data further (e.g. split execution columns into `dynamic_run_
  executions`), the fingerprint FK moves to whichever table still owns
  that column. CASCADE behavior stays.

---

## 7. Draft SQL

Constraint-only snippets. Column ordering, column names, table identity,
and non-constraint columns are out of scope (A1/A5 own those). The snippets
below show the **constraint declarations** that should appear on the v100
tables. Column stubs (`…`) indicate "whatever A1/A5 settle on for this
column plus its type annotation".

### 7a. Top of `initDb()` (before migrations run)

```ts
db.pragma("foreign_keys = ON");
```

### 7b. findings

```sql
CREATE TABLE findings (
  fingerprint TEXT PRIMARY KEY,
  …,
  verdict TEXT NOT NULL
    CHECK (verdict IN ('tp','fp','needs_review','by_design')),
  confidence REAL NOT NULL
    CHECK (confidence >= 0 AND confidence <= 1),
  task_id TEXT NOT NULL,  -- drop legacy default 'semgrep'
  …,
  verify_exploitable INTEGER
    CHECK (verify_exploitable IS NULL OR verify_exploitable IN (0,1)),
  poc_harness_parsed INTEGER
    CHECK (poc_harness_parsed IS NULL OR poc_harness_parsed IN (0,1)),
  poc_harness_skipped INTEGER
    CHECK (poc_harness_skipped IS NULL OR poc_harness_skipped IN (0,1)),
  poc_run_verdict TEXT
    CHECK (poc_run_verdict IS NULL
           OR poc_run_verdict IN ('PASS','FAIL','ERROR','TIMEOUT')),
  proof_state TEXT
    CHECK (proof_state IS NULL
           OR proof_state IN ('symbolic_only','inconclusive',
                              'execution_attempted','execution_rejected',
                              'execution_confirmed')),
  -- NOT NULL on: repo, ref, rule_id, file_path, start_line, severity,
  -- message, rationale, verification_steps, created_at, updated_at, task_id
  …
);
```

### 7c. pipeline_runs

```sql
CREATE TABLE pipeline_runs (
  run_id TEXT PRIMARY KEY,
  repo TEXT NOT NULL,
  started_at TEXT NOT NULL,
  status TEXT NOT NULL
    CHECK (status IN ('scanning','triaging','verifying','poc-harnessing',
                      'dynamic-analyzing','complete','error','aborted')),
  config_json TEXT NOT NULL,
  scan_opts_json TEXT NOT NULL,
  total_cost_usd REAL NOT NULL DEFAULT 0,
  …
);
```

### 7d. dynamic_analysis_runs

```sql
CREATE TABLE dynamic_analysis_runs (
  dynamic_run_id TEXT PRIMARY KEY,
  pipeline_run_id TEXT
    REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
  fingerprint TEXT NOT NULL
    REFERENCES findings(fingerprint) ON DELETE CASCADE,
  repo TEXT NOT NULL,
  status TEXT NOT NULL
    CHECK (status IN ('confirmed','interesting','rejected','error')),
  score REAL NOT NULL DEFAULT 0,
  proof_value REAL NOT NULL DEFAULT 0,
  coverage_mode TEXT
    CHECK (coverage_mode IS NULL
           OR coverage_mode IN ('none','node-v8','python-coverage')),
  execution_verdict TEXT
    CHECK (execution_verdict IS NULL
           OR execution_verdict IN ('PASS','FAIL','ERROR','TIMEOUT')),
  iterations INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 7e. patch_results

```sql
CREATE TABLE patch_results (
  patch_run_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL
    REFERENCES findings(fingerprint) ON DELETE CASCADE,
  repo TEXT NOT NULL,
  status TEXT NOT NULL
    CHECK (status IN ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE',
                      'TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')),
  iterations INTEGER NOT NULL DEFAULT 1,
  history_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 7f. crypto_behavioral_runs

```sql
CREATE TABLE crypto_behavioral_runs (
  run_id TEXT PRIMARY KEY,
  pipeline_run_id TEXT
    REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
  fingerprint TEXT NOT NULL
    REFERENCES findings(fingerprint) ON DELETE CASCADE,
  repo TEXT NOT NULL,
  test_type TEXT NOT NULL
    CHECK (test_type IN ('timing','ecb-mode','weak-hash','weak-prng',
                         'key-length','edge-case')),
  verdict TEXT NOT NULL
    CHECK (verdict IN ('vulnerable','secure','inconclusive','error')),
  execution_verdict TEXT
    CHECK (execution_verdict IS NULL
           OR execution_verdict IN ('PASS','FAIL','ERROR','TIMEOUT')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 7g. finding_assertions

```sql
CREATE TABLE finding_assertions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL
    REFERENCES pipeline_runs(run_id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL
    REFERENCES findings(fingerprint) ON DELETE CASCADE,
  assertion_name TEXT NOT NULL,
  passed INTEGER NOT NULL CHECK (passed IN (0,1)),
  score REAL NOT NULL,
  weight REAL NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 7h. trajectories

```sql
CREATE TABLE trajectories (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  verdict TEXT NOT NULL
    CHECK (verdict IN ('tp','fp','needs_review','by_design')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  was_correct INTEGER
    CHECK (was_correct IS NULL OR was_correct IN (0,1)),
  repo TEXT NOT NULL,
  fingerprint TEXT
    REFERENCES findings(fingerprint) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
  -- steps_json, cwes_json, summary all NOT NULL
);
```

### 7i. code_graph_nodes / _edges / _paths

```sql
CREATE TABLE code_graph_nodes (
  node_id TEXT PRIMARY KEY,
  …,
  node_kind TEXT NOT NULL
    CHECK (node_kind IN (
      'entry-http','entry-cli','entry-event','entry-cron',
      'entry-background','middleware','controller','service',
      'data-access','external-call','sanitizer','validator',
      'transformer','unknown')),
  source TEXT NOT NULL DEFAULT 'static'
    CHECK (source IN ('static','llm','hybrid'))
);

CREATE TABLE code_graph_edges (
  edge_id TEXT PRIMARY KEY,
  …,
  from_node_id TEXT NOT NULL
    REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
  to_node_id TEXT NOT NULL
    REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
  edge_kind TEXT NOT NULL
    CHECK (edge_kind IN (
      'calls','imports','middleware-chain','callback','promise-chain',
      'event-emit','event-listen','di-inject','dynamic-dispatch',
      'data-flow','config-read','serialization')),
  source TEXT NOT NULL DEFAULT 'static'
    CHECK (source IN ('static','llm','hybrid'))
);

CREATE TABLE code_graph_paths (
  path_id TEXT PRIMARY KEY,
  …,
  entry_node_id TEXT NOT NULL
    REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
  target_node_id TEXT NOT NULL
    REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
  has_sanitizer INTEGER NOT NULL DEFAULT 0
    CHECK (has_sanitizer IN (0,1)),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1)
);
```

### 7j. workspaces / workspace_snapshots

Already constraint-correct once PRAGMA is on. No SQL changes.

```sql
CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  …
);

CREATE TABLE workspace_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_id TEXT NOT NULL
    REFERENCES workspaces(id) ON DELETE CASCADE,
  …
);
```

### 7k. calibration_weights

Already constraint-correct. No changes.

```sql
CREATE TABLE calibration_weights (
  step_type     TEXT NOT NULL,
  rule_family   TEXT NOT NULL,
  weight        REAL NOT NULL DEFAULT 1.0,
  sample_count  INTEGER NOT NULL DEFAULT 0,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (step_type, rule_family)
);
```

---

## Verification checklist (self-audit)

- [x] `findings.verdict` CHECK explicitly expanded to include
      `'by_design'`.
- [x] Every proposed FK specifies an ON DELETE mode
      (CASCADE / SET NULL — RESTRICT deliberately unused).
- [x] PRAGMA section cites current observed values at
      `src/store.ts:119–136` and specifies the single change
      (`foreign_keys = ON`) + its placement.
- [x] Every proposed constraint is backed by either (a) grep-verified app
      behavior that already writes conforming values, or (b) a flagged
      TS-vs-DB divergence documented in §3.
- [x] Composite UNIQUE claim for `(repo, ref, fingerprint)` evaluated —
      rejected as redundant given fingerprint's deterministic hash inputs
      (§1b findings entry). PK on fingerprint alone is kept.
- [x] `calibration_weights` composite PK confirmed (§1b, §7k).
- [x] `workspaces.name` UNIQUE confirmed (§1b, §7j).
