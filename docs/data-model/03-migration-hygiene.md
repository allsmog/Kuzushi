# Migration Hygiene & v100 Reset Design — Agent 3

Dimension: **Migration mechanics** (per `_column-ownership.md`). This doc audits the 25 shipped migrations, specifies how the v100 schema reset works, and lays down a style guide for future migrations.

Sibling docs (other dimensions):

- `01-consolidation-and-naming.md` — Agent 1 (naming + TS shape)
- `02-dead-code.md` — Agent 2 (liveness / drops)
- `04-constraints.md` — Agent 4 (CHECK / NOT NULL / UNIQUE / FK)
- `05-denormalization.md` — Agent 5 (table splits / JSON extraction)

Evidence citations use `path/to/file.ts:line` format per the coordination doc.

---

## 1. Audit: migrations 001–025

Legend for **severity**:

- **none** — clean migration, would pass any future review.
- **low** — cosmetic concern (e.g. inconsistent idempotency style) with no behavioural impact.
- **med** — real hazard on some DBs but no incidents observed (e.g. no backfill of a newly-tightened CHECK, but the CHECK happens to pass for all real data).
- **high** — known defect that has actually broken or nearly broken upgrades (e.g. migration 024 exists because of the 002 rename incident).

Risky-pattern codes used in the "risky patterns" column:

- `NT` — non-transactional backfill (DDL + UPDATE outside `migration.up`)
- `CT` — CHECK tightening without a backfill pass
- `NI` — non-idempotent DDL (e.g. `CREATE TABLE` without `IF NOT EXISTS`, or `ALTER ADD COLUMN` without a legacy-column guard)
- `ND` — missing DEFAULT on a NOT NULL column added to an existing table
- `IC` — index churn (created/dropped/re-created across versions)
- `AD` — depends on runtime app behaviour (service up, env vars, etc.)
- `RC` — recreate-table pattern (drop + copy); correct but easy to get wrong

| version | name | risky patterns found | severity | notes |
|---|---|---|---|---|
| 001 | `initial_schema` | none | **none** | Uses `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`. `findings.verdict` CHECK is `('tp','fp','needs_review')` — later widened to include `'by_design'` at the TS layer but never in SQL (see Agent 4). Not a migration-hygiene bug; a constraints bug. `findings.severity` has no CHECK — Agent 4's call. |
| 002 | `add_task_id_column` | NI (defensive) | **low** | Column was originally `scanner`, then the file was later rewritten in-place to add `task_id` instead. DBs initialised pre-rewrite have `scanner`; DBs initialised post-rewrite have `task_id`. Migration 024 exists purely to clean up the resulting split. Lesson: **never rewrite a shipped migration's DDL under the same version number.** The `IF NOT EXISTS` guard on the column check does mitigate re-runs. |
| 003 | `add_triage_cost_column` | none | **none** | Guarded `ALTER TABLE ADD COLUMN`, nullable REAL — safe on existing rows. |
| 004 | `add_triage_details_column` | none | **none** | Same pattern as 003. |
| 005 | `add_verification_columns` | none | **none** | Adds 7 nullable columns in a loop with a name-set guard; all nullable, so no `ND`. |
| 006 | `add_poc_harness_columns` | none | **none** | Same pattern as 005. |
| 007 | `add_poc_execution_columns` | none | **none** | Same pattern as 005/006. |
| 008 | `pipeline_runs_status_values` | CT, RC | **med** | Recreates `pipeline_runs` to widen the status CHECK. No backfill pass: relies on the assumption that every existing row already has a status value in the widened set (`scanning/triaging/complete/error` were the old values; widened set is a superset, so in practice rows pass — **but** the migration doesn't verify this). The RC pattern itself is correct (create `_v2`, copy, drop, rename), and it guards both `?.sql` being missing and the CHECK already being widened. Also inserts `context_json` conditionally — the `context_json` column handling is a soft contract with migration 009. |
| 009 | `add_pipeline_runs_context` | none | **low** | Adds `context_json` with an idempotent guard. Subtle coupling with 008: if 008 ran on a fresh DB it already created `context_json`; if 008 ran on an existing DB and the column wasn't there, 008 wrote `NULL`; 009 is the explicit backfill column-adder. Works, but the dependency is implicit. |
| 010 | `add_calibration_schema` | none | **none** | New table (IF NOT EXISTS) + two guarded column adds. Nullable columns, safe. |
| 011 | `add_trajectories_table` | none | **none** | Single `CREATE TABLE IF NOT EXISTS` + indexes. |
| 012 | `add_finding_provenance_columns` | none | **none** | Three guarded column adds; all nullable. |
| 013 | `add_composite_confidence_columns` | none | **none** | Two guarded column adds; all nullable. |
| 014 | `add_metrics_column` | none | **none** | Single guarded `ALTER TABLE ADD COLUMN`. |
| 015 | `add_assertion_tracking` | none | **low** | Mixes `db.prepare(...).run()` and `db.exec(...)` styles within the same migration — purely cosmetic but makes the file read inconsistently with its neighbours. `finding_assertions.run_id` should be a FK to `pipeline_runs.run_id` (Agent 4's territory). |
| 016 | `add_structured_finding_evidence` | none | **none** | Three guarded column adds; all nullable. `proof_state` is stored as untyped TEXT with no CHECK — Agent 4's territory. |
| 017 | `add_dynamic_and_patch_persistence` | none | **low** | Clean create-table-IF-NOT-EXISTS. `patch_results.status` CHECK is tightened again in 020 — so `patch_results` has had two CHECK rewrites in the life of the project (see 020). `dynamic_analysis_runs.fingerprint` and `patch_results.fingerprint` are stored without FKs to `findings.fingerprint` — Agent 4. |
| 018 | `add_crypto_behavioral_runs` | none | **none** | Clean create-table. No CHECK on `verdict` / `test_type` — Agent 4. |
| 019 | `add_code_graph_tables` | none | **none** | Three tables with `REFERENCES` declarations. **BUT** — `PRAGMA foreign_keys` is not enabled anywhere in `initDb()` (`src/store.ts:119-136`), so the FKs declared here are **advisory only at runtime**. The schema documents intent but SQLite silently ignores FK violations. Not a migration-mechanics bug (the declarations are correct); it's an initDb-setup bug. Agent 4 should require `PRAGMA foreign_keys = ON` in `initDb()`. |
| 020 | `add_verified_patch_status` | RC | **low** | Recreate-table pattern to widen `patch_results.status` CHECK. Uses `INSERT INTO patch_results SELECT * FROM patch_results_old` — positionally coupled to column order. If 017's column order and 020's column order ever disagreed, this would silently misalign. They match today, but the pattern is fragile; prefer explicit column lists like 023 uses. |
| 021 | `add_incremental_scanning_support` | none | **none** | Guarded column add + index create. |
| 022 | `add_verdict_index` | none | **none** | Single `CREATE INDEX IF NOT EXISTS`. |
| 023 | `expand_pipeline_status_constraint` | CT, RC | **med** | Same shape as 008, targeting the same table. `pipeline_runs` has now been fully rebuilt **twice** (008, 023) plus had columns added incrementally (009, 014, 015, 021). Six migrations touch one table. Uses an explicit column list and filters to existing columns only — safer than 020's positional copy. Still no row-level backfill: assumes no row has a status outside the new widened set (true in practice because the new set is a superset of the previous). |
| 024 | `rename_scanner_to_task_id` | none | **high (historical)** | Compensates for the 002 rewrite. The migration itself is clean (guarded `RENAME COLUMN`, re-drops `idx_scanner`, recreates `idx_task_id`). Severity is "high" because of the **root cause** — migration 002 was edited after shipping — not because 024 itself is bad. Lesson encoded in Style Guide rule #2 below. |
| 025 | `add_workspaces_table` | none | **none** | Clean `CREATE TABLE IF NOT EXISTS`. FK with `ON DELETE CASCADE` — again inert unless `PRAGMA foreign_keys = ON`. |

### Cross-cutting audit observations

1. **`PRAGMA foreign_keys` is OFF.** `initDb()` at `src/store.ts:119-136` sets `journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, but never `foreign_keys=ON`. Every `REFERENCES` declaration in migrations 019 and 025 is decorative. Agent 4 must require the pragma in the reset plan.
2. **No backfill pass anywhere.** All 25 migrations are DDL-only. No migration updates row values. This worked because every widened CHECK was a superset and every new column was nullable-with-default. Future migrations will not all fit that shape — rule #6 below addresses it.
3. **Six migrations touch `pipeline_runs`.** 001, 008, 009, 014, 015, 021, 023. Two of those (008, 023) fully recreate the table. The current schema for this table can only be understood by reading all six files in order. The v100 reset collapses this to a single `CREATE TABLE`.
4. **No incident of a truly data-destructive migration.** The bar is low, but credit where due: nothing has silently dropped user data. The `scanner → task_id` incident broke upgrades cleanly (column missing on new reads) rather than corrupting rows.
5. **Intel tables live outside migrations.** `createIntelTables()` in `src/intel/store.ts:21` is called ad-hoc, not as a versioned migration. This means `intel_documents` and `intel_fts` have no entry in `schema_version` and cannot be audited via the migration trail. The v100 reset should fold these into the versioned migration.
6. **Runner wraps each migration in a transaction.** `runner.ts:219-229` — `db.transaction(() => { migration.up(db); ... })()`. This means rule #3 below (no nested transactions) is enforced by convention, not by the type system. Safe, but the `Migration.up` doc-comment at `src/migrations/types.ts:10` should state it explicitly.

---

## 2. v100 reset design

### 2.1 Where the decision lives

Today: `src/store.ts:119-136` defines `initDb()`. It opens the DB, sets pragmas, calls `runMigrations()`, checkpoints WAL, returns.

The reset decision belongs **between pragmas and `runMigrations()`** in `initDb()` — that way, pragmas (WAL + busy_timeout) are already in place if we need to back up the DB with file handles open, and `runMigrations()` runs exactly once, against either the fresh DB (the reset branch) or an already-v100 DB (the no-op branch).

### 2.2 `initDb()` pseudocode (file:line anchor = `src/store.ts:119`)

```ts
// src/store.ts:119
export function initDb(dbPath: string, opts?: InitDbOpts): Database.Database {
  let db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");          // NEW — Agent 4 requirement, enforced here

  // --- NEW: v100 reset branch ---
  const state = inspectSchemaState(db);    // see 2.3
  if (state.kind === "legacy-pre-v100") {
    // Close handle so we can safely rename the file.
    db.close();
    const backupPath = computeBackupPath(dbPath, state.version);
    renameWithCollisionSuffix(dbPath, backupPath);  // see 2.6
    logReset({ oldVersion: state.version, backupPath });   // see 2.7
    // Re-open a fresh DB at the same path.
    db = new Database(dbPath);
    db.pragma("journal_mode = WAL");
    db.pragma("busy_timeout = 5000");
    db.pragma("synchronous = NORMAL");
    db.pragma("foreign_keys = ON");
  }
  // --- end reset branch ---

  runMigrations(db, allMigrations);        // now always either runs v100 on a fresh DB,
                                           // or is a no-op on an already-v100 DB
  db.pragma("wal_checkpoint(TRUNCATE)");
  return db;
}
```

`InitDbOpts` is optional and exists only to let tests inject a clock for deterministic timestamps and skip the `renameWithCollisionSuffix` step when seeding. Production callers pass nothing.

### 2.3 State detection — `inspectSchemaState(db)`

Four terminal states. Precedence top-down:

| state.kind | detection | action |
|---|---|---|
| `fresh` | `schema_version` table does not exist AND `findings` table does not exist | no reset; `runMigrations()` applies v100 against an empty DB |
| `already-v100` | `schema_version` has a row with `version = 100` | no-op; `runMigrations()` sees v100 already applied and short-circuits |
| `legacy-pre-v100` | `findings` table exists AND (no `schema_version` row OR max `schema_version.version < 100`) | reset branch: backup + fresh DB |
| `corrupt` | SQLite error on the `PRAGMA table_info(findings)` probe, OR `schema_version` exists but contains `version > 100` (i.e. a future version that shouldn't be here) | throw `SchemaStateError` with the DB path and a pointer to `kuzushi db migrate-from-bak` (future CLI) |

Pseudocode:

```ts
function inspectSchemaState(db: Database.Database): SchemaState {
  try {
    const hasSchemaVersion = tableExists(db, "schema_version");
    const hasFindings     = tableExists(db, "findings");

    if (!hasSchemaVersion && !hasFindings) return { kind: "fresh" };

    const maxVersion = hasSchemaVersion
      ? (db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as { v: number | null }).v ?? 0
      : 0;

    if (maxVersion > 100) return { kind: "corrupt", reason: `version ${maxVersion} > 100` };
    if (maxVersion === 100) return { kind: "already-v100" };

    // hasFindings is implied: either there's a findings table from legacy,
    // or there's a schema_version < 100 which means pre-reset.
    return { kind: "legacy-pre-v100", version: maxVersion };
  } catch (err) {
    return { kind: "corrupt", reason: String(err) };
  }
}
```

Note: the `fresh` state bypasses the reset branch entirely. The `runMigrations()` call applies v100 (and only v100, if we delete 001–025 from `allMigrations` — see 2.9) against an empty DB. Behaviour is indistinguishable from the reset branch except that no backup file is produced.

### 2.4 Backup path function

Signature:

```ts
function computeBackupPath(dbPath: string, oldVersion: number, now = new Date()): string;
```

Format: `<dbPath>.bak-v<oldVersion>-<YYYYMMDDTHHmmss>`

Timestamp is UTC, `toISOString()` with `:` and `-` and `.xxxZ` stripped, ending at seconds precision. Rationale: filename-safe on Windows/macOS/Linux, sorts lexically in chronological order, and collision-free on all typical upgrade paths (one reset per second per DB is the practical worst case).

Examples:

- `index.sqlite3` + oldVersion 25 + `2026-04-16T14:23:07.123Z` → `index.sqlite3.bak-v25-20260416T142307`
- oldVersion 0 (legacy DB with `findings` table but empty `schema_version`) → `index.sqlite3.bak-v0-20260416T142307`

### 2.5 Concurrency: two `kuzushi` processes hitting the same DB

`better-sqlite3` is synchronous, but two processes *can* each open the same file. Scenarios:

1. **Both see `legacy-pre-v100`.** First process grabs the file handle, inspects, closes, renames, re-opens fresh, runs v100. Second process — if it opened before the rename — now holds a handle to a file that no longer has that path. The second process's subsequent writes go into the now-renamed `.bak` file (on POSIX; Windows will have blocked the rename while the handle was open). This is **data loss** for the second process's writes, but the reset branch makes them land in the backup where they can be recovered manually.
2. **Race: first process has closed the old DB, about to rename; second process sees the same `legacy-pre-v100` and wants to open.** If both call `renameWithCollisionSuffix` they'll collide — mitigated by the collision suffix (see 2.6). Only one rename wins; the other gets an EEXIST that we retry with a suffix.
3. **Both see `already-v100`.** No reset. Standard better-sqlite3 concurrency applies (WAL + busy_timeout=5000 handle it). No new risk.
4. **Both see `fresh`.** No reset, but both try to run v100 against an empty DB. `runMigrations()` is transactional per migration (`runner.ts:219-229`); whichever process commits first, the second one sees `schema_version.version = 100` inside its own transaction's view and skips. The `INSERT INTO schema_version (100, 'schema_reset', ...)` statement has `PRIMARY KEY (version)` so the second insertion would fail with a constraint error — which would roll back the transaction cleanly (the table was already created by the first process). We must explicitly handle this: wrap the v100 migration's `schema_version` insert in `INSERT OR IGNORE`, or — simpler — check `schema_version` **inside the transaction** before creating any tables.

**Concrete mitigation:**

- Add a file-lock advisory step: before the reset branch, try to `fs.writeFileSync(dbPath + ".reset-lock", pid, { flag: "wx" })`. If it fails with EEXIST, wait on a polling loop (up to 30s) for the other process to finish, then re-inspect state. This is the same pattern used for git index locks. If the wait times out, throw with a message pointing to the lock file for manual recovery.
- The lock file is removed in a `finally` block after the reset branch completes (whether it succeeded or threw).
- For the `fresh` state race (case 4): rely on `runMigrations()`'s per-migration transaction. The second process's transaction rolls back the duplicate insert cleanly. (No code change needed in runner.)

### 2.6 Filesystem edge cases

| scenario | behaviour |
|---|---|
| readonly filesystem | `fs.renameSync` throws EROFS. We catch, log an error pointing at the DB path, and **refuse to open the DB** — returning an error rather than silently running the scan against a legacy schema. Specifically, we throw `ReadOnlyDbError` with `dbPath` and a suggestion: "move the DB to a writable location or run with `--db-path`". |
| insufficient permissions on the backup path | `fs.renameSync` throws EACCES. Same behaviour as EROFS — refuse to open. |
| existing `.bak-*` file collision | `renameWithCollisionSuffix` appends `-1`, `-2`, … until the destination doesn't exist. Cap at 10 retries to avoid infinite loops on pathological filesystems; beyond 10, throw. |
| disk full during rename | EIO/ENOSPC — refuse to open, bubble up the error. |
| DB file is 0 bytes | Treated as `fresh` (no `findings` table, no `schema_version` table). Safe. |
| DB file is garbage | `new Database(dbPath)` throws on first query (`tableExists` probe). Caught by `inspectSchemaState`, returned as `{ kind: "corrupt" }`. Caller throws `SchemaStateError`. |
| parent directory doesn't exist | `new Database()` will create it on most platforms; if not, throws. Existing behaviour unchanged. |

`renameWithCollisionSuffix` pseudocode:

```ts
function renameWithCollisionSuffix(src: string, dst: string, maxRetries = 10): string {
  let attempt = dst;
  for (let i = 0; i < maxRetries; i++) {
    try { fs.renameSync(src, attempt); return attempt; }
    catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") {
        attempt = `${dst}-${i + 1}`;
        continue;
      }
      throw err;  // EROFS / EACCES / ENOSPC / etc. — surface to caller
    }
  }
  throw new Error(`Could not find a free backup path after ${maxRetries} attempts: ${dst}`);
}
```

### 2.7 User messaging

`logReset({ oldVersion, backupPath })` must render the reset banner once per run. Output surface depends on the renderer (per `CLAUDE.md` Terminal UI section):

| context | surface |
|---|---|
| Ink UI mode (`"preflight"` / `"running"`) | push a `UIState.preflight.notices` entry: `{ level: "warn", text: "Schema reset: renamed to <backupPath>. Previous findings are in the backup." }`. Rendered by `App.tsx` preflight panel. |
| Plain renderer (non-TTY) | `plain-renderer.ts` emits one line: `kuzushi: schema reset v<oldVersion> → v100; backup at <backupPath>`. |
| Completely TTY-less fallback (e.g. CI piping) | the plain renderer's `console.log` path still fires. |
| Test harness | `InitDbOpts.onReset?(info)` callback — tests pass a spy, assert on info. No `console.log`. |

Never use `console.log` directly from `store.ts`. The reset logger accepts an injected sink (default: resolves via `src/ui/plain-renderer.ts`) so the message routes through the UI stack consistently.

### 2.8 Hook point for `kuzushi db migrate-from-bak` (future CLI, not implemented)

The backup filename encodes the old schema version: `index.sqlite3.bak-v25-20260416T142307`. A future `kuzushi db migrate-from-bak <path>` subcommand parses the `v<N>-` segment, opens the backup read-only, reads rows out of old tables, and upserts them into the new DB through the normal store API (which applies the new CHECK constraints and normalisation). The hook is purely a filename contract — no new code is required in `store.ts` today.

Design note so a future implementer doesn't have to rediscover: the backup file must be treated as **read-only** — never run migrations against it (it's a snapshot of the pre-v100 world). The CLI should open it with `new Database(path, { readonly: true })`.

### 2.9 `runner.ts` changes

Two small changes needed:

1. **Delete migrations 001–025 from `allMigrations`.** The legacy-detection heuristic in `detectAndMarkLegacyDatabase()` at `runner.ts:33-188` becomes dead code (the reset branch runs before `runMigrations()`, so by the time `runMigrations()` runs the DB is either fresh or already-v100). We can either delete the whole function or leave it in place as defensive code and rely on the fact that it'll do nothing (no `findings` table exists on a freshly-reset DB). **Recommendation: delete it in the same commit that adds v100.** It's confusing to keep around.
2. **`runner.ts` does not need to know about the reset.** The reset branch is entirely in `initDb()`. The runner keeps its contract: given a DB and a migration list, apply any unapplied migrations in order inside transactions. This preserves the mechanical simplicity of the runner — a testable primitive that doesn't understand "reset".

Diff sketch for `src/migrations/index.ts`:

```ts
// src/migrations/index.ts — new
export { runMigrations } from "./runner.js";
export type { Migration } from "./types.js";

import { migration100 } from "./100_schema_reset.js";

/** All registered migrations in version order. */
export const allMigrations: Migration[] = [migration100];
```

Migrations 001–025 .ts files stay in the tree for historical reference (git blame, forensics, archaeology) but are not imported anywhere. Optionally move them to `src/migrations/_legacy/` if we want to make the distinction visually obvious.

---

## 3. Style guide for future migrations

Concise rulebook. Every rule has a one-line example.

1. **One version, one file, one immutable record.** Once a migration is in `main`, its `.up` is frozen. If you need to change behaviour, add a new migration. *Example:* don't rewrite `002` to rename a column — add `026` that does the rename (cf. the 002→024 incident).

2. **Never reuse a version number.** Not even for "typos". Each integer is permanent. *Example:* if `026` is reverted before release, the next migration is still `027`.

3. **The runner wraps each migration in a transaction — don't nest.** `src/migrations/runner.ts:219-229` runs `migration.up(db)` inside `db.transaction(...)`. Do not call `BEGIN`/`COMMIT` or `db.transaction()` inside your `up`. *Example:* `db.exec("ALTER TABLE ...")` is correct; `db.transaction(() => db.exec("ALTER TABLE ..."))()` is wrong (would nest).

4. **DDL must be idempotent.** Use `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`, and the `PRAGMA table_info(<table>)` guard before `ALTER TABLE ADD COLUMN`. *Example:* see `002` lines 7-11 for the column-add guard pattern; reproduce it verbatim.

5. **New NOT NULL columns on existing tables need a DEFAULT.** SQLite will reject rows without a value. *Example:* `ALTER TABLE findings ADD COLUMN task_id TEXT NOT NULL DEFAULT 'semgrep'` (from `002`), not `... TEXT NOT NULL`.

6. **Backfills come after the DDL in the same migration.** If the column needs computed values after creation, run an `UPDATE` in the same `up()` — it's already inside the runner's transaction. *Example:* `db.exec("UPDATE findings SET severity_score = CASE severity WHEN 'high' THEN 3 ... END WHERE severity_score IS NULL")` after adding the column nullable.

7. **Never tighten a CHECK constraint on existing data.** SQLite does not support `ALTER CHECK`; widening needs the recreate-table dance (see `008`, `020`, `023`). *Tightening* (removing allowed values) is even worse — it can reject real rows. If you need to tighten, do it only at a reset boundary (v100, next time v200). *Example:* don't shrink `verdict IN ('tp','fp','needs_review','by_design')` back down — reserve the change for a reset.

8. **CHECK widening uses the "_vN" recreate pattern, with an explicit column list.** Follow `023` (explicit column filter), not `020` (positional `SELECT *`). *Example:* `INSERT INTO pipeline_runs_vN (run_id, repo, ...) SELECT run_id, repo, ... FROM pipeline_runs` — never `SELECT *`.

9. **Indexes and triggers live in the same migration as the table they depend on.** Don't split a table's creation and its indexes across two migrations unless there's a schema-versioning reason. *Example:* `019` creates three tables with their indexes in one `db.exec(...)` block.

10. **`ALTER TABLE RENAME COLUMN` needs SQLite ≥ 3.25.** Document that in the migration's doc-comment. *Example:* see `024:13` header comment.

11. **Migrations must not depend on app services.** No network calls, no readFile of code under scan, no access to `process.env`. A migration's inputs are the DB and its outputs are the DB. *Example:* don't read `~/.kuzushi/config.json` inside a migration.

12. **Test every migration by seeding a pre-migration DB.** Add `tests/migrations/<NNN>_<name>.test.ts`. Open an in-memory DB, apply migrations `[1..N-1]`, seed representative rows, apply `N`, assert on resulting rows and schema. *Example:* the new `tests/migrations/schema-reset.test.ts` (see Phase C plan, item 3) does this for v100.

13. **Do not write to the filesystem inside a migration.** Reset-style file operations belong in `initDb()`, not in `migration.up`. *Example:* backup-and-rename lives in `initDb()`; the v100 migration's `up()` only touches the DB.

14. **Write the migration's doc-comment as a user-facing changelog line.** The first line of the JSDoc is what will show up when someone asks `git log --oneline src/migrations/`. *Example:* `/** Add `task_id` column to findings (defaulted to 'semgrep'). */` (from `002:3`).

15. **Reset vs incremental: reset when three or more migrations target the same table for structural reasons, or when the app-level model diverges from the DB-level model.** Otherwise, always prefer a new incremental migration. Resets are expensive (user DB backup, reset-lock handling, cross-agent coordination) and should happen on the order of once a year, not monthly. *Example:* the current cleanup (25 migrations, 6 of them on `pipeline_runs`, plus the `adjusted_score` / `triage_details_json` denormalisation issues) is a reset-worthy situation. A single new `corroboration_source` column would not be.

---

## 4. Cross-cutting observations

Space-reservation notes for the v100 reset SQL, so Agents 1, 4, and 5 can compose their output without conflicts:

- **Agent 1 (naming).** A1 renames at the DB↔TS boundary go inside the `CREATE TABLE` column list in `100_schema_reset.ts` — the single place column names appear. A1 does not emit `ALTER TABLE RENAME COLUMN` statements because v100 is a reset, not an incremental. All renames are "new schema is written this way". The migration file is A1's sole output target for SQL.

- **Agent 4 (constraints).** A4's CHECK / NOT NULL / UNIQUE clauses get appended to the column definitions and `CONSTRAINT` lines inside the `CREATE TABLE` statements A1 writes. A4 also owns the standalone `CREATE UNIQUE INDEX` statements (e.g. composite UNIQUE on `(repo, ref, fingerprint)` per the plan). A4's `PRAGMA foreign_keys = ON` lands in `initDb()` at `src/store.ts:119` — shown in my 2.2 pseudocode — and once it's there, every `REFERENCES` declaration written by A1 becomes enforced.

- **Agent 5 (structure).** A5's extracted tables (e.g. a normalised `finding_costs` instead of `triage_cost_usd` / `verify_cost_usd` / `poc_*_cost_usd` columns on `findings`, or extracted threat-modeling fields out of `triage_details_json`) go in the **same** `100_schema_reset.ts` file. A5 writes additional `CREATE TABLE` statements; A1 names those tables and their columns; A4 constrains them. A5 also owns the decision to **delete** legacy columns that migrations 001–025 added but are now redundant post-extraction — those columns simply don't appear in the v100 `CREATE TABLE`.

- **Mechanical reservation inside `100_schema_reset.ts`.** The migration is a single `db.exec(...)` containing one `CREATE TABLE` per canonical table, plus indexes, plus the intel tables (moved out of `src/intel/store.ts:21`). Suggested ordering for diff readability:
  1. Core findings table (A1 + A4 + A5 decisions)
  2. Pipeline runs table (merges the effects of 001/008/009/014/015/021/023)
  3. Calibration + trajectories (simple)
  4. Per-module: dynamic_analysis_runs, patch_results, crypto_behavioral_runs
  5. Code graph (nodes, edges, paths — with real FKs)
  6. Workspaces + workspace_snapshots
  7. Intel documents + intel_fts (migrated in from `src/intel/store.ts:21`)
  8. `finding_assertions` (with FK to pipeline_runs)
  9. Any A5 side-tables (e.g. `finding_costs`) at the end so the core tables read cleanly at the top

- **Intel tables.** Today `createIntelTables()` in `src/intel/store.ts:21-45` runs ad-hoc. The v100 reset is the right moment to fold these into the migration trail. After v100 ships: delete the ad-hoc call site and let `initDb()` → `runMigrations()` handle it.

- **The `detectAndMarkLegacyDatabase` heuristic.** `runner.ts:33-188` becomes dead code after v100 lands. Remove it in the same commit so nobody reads it and copies the pattern.

---

## 5. Draft SQL / pseudocode — skeleton

### 5.1 `src/migrations/100_schema_reset.ts` (skeleton — other agents fill in their dimensions)

```ts
import type { Migration } from "./types.js";

/**
 * v100 schema reset.
 *
 * Consolidated replacement for migrations 001–025. This migration runs against
 * a *fresh* database only — the reset branch in `initDb()` ensures any legacy
 * DB has been renamed to `index.sqlite3.bak-v<old>-<ts>` before we get here.
 *
 * Composition:
 *   - [A1] Column names / types at the DB↔TS boundary
 *   - [A2] Columns dropped vs retained (the `CREATE TABLE`s below omit drops)
 *   - [A4] CHECK / NOT NULL / UNIQUE / FK clauses on each column
 *   - [A5] Table split/merge decisions; extracted side-tables at the bottom
 */
export const migration100: Migration = {
  version: 100,
  name: "schema_reset",
  up(db) {
    db.exec(`
      -- =======================================================================
      -- 1. findings  (A1 naming, A4 constraints, A5 structure)
      -- =======================================================================
      CREATE TABLE findings (
        -- [A1 owns column names + types]
        -- [A4 appends CHECK / NOT NULL / UNIQUE clauses here]
        -- [A5 owns decision to keep vs extract JSON blobs]
      );

      -- [A4 owns] Composite UNIQUE on (repo, ref, fingerprint), indexes, etc.
      CREATE UNIQUE INDEX ... ;
      CREATE INDEX ... ;

      -- =======================================================================
      -- 2. pipeline_runs  (collapses 001/008/009/014/015/021/023)
      -- =======================================================================
      CREATE TABLE pipeline_runs ( /* [A1 + A4 + A5] */ );
      CREATE INDEX ... ;

      -- =======================================================================
      -- 3. calibration_weights, trajectories, finding_assertions
      -- =======================================================================
      CREATE TABLE calibration_weights ( /* [A1 + A4] */ );
      CREATE TABLE trajectories        ( /* [A1 + A4] */ );
      CREATE TABLE finding_assertions  ( /* [A1 + A4 — FK on run_id] */ );

      -- =======================================================================
      -- 4. dynamic_analysis_runs, patch_results, crypto_behavioral_runs
      -- =======================================================================
      CREATE TABLE dynamic_analysis_runs  ( /* [A1 + A4 + A5 — FK on fingerprint] */ );
      CREATE TABLE patch_results          ( /* [A1 + A4 — status widened CHECK] */ );
      CREATE TABLE crypto_behavioral_runs ( /* [A1 + A4 — verdict/test_type CHECK] */ );

      -- =======================================================================
      -- 5. code_graph_{nodes,edges,paths} (FKs enforced now that pragma is ON)
      -- =======================================================================
      CREATE TABLE code_graph_nodes ( /* [A1 + A4 — node_kind CHECK] */ );
      CREATE TABLE code_graph_edges ( /* [A1 + A4 — edge_kind CHECK, FKs to nodes] */ );
      CREATE TABLE code_graph_paths ( /* [A1 + A4 — FKs to nodes] */ );

      -- =======================================================================
      -- 6. workspaces, workspace_snapshots
      -- =======================================================================
      CREATE TABLE workspaces           ( /* [A1 + A4] */ );
      CREATE TABLE workspace_snapshots  ( /* [A1 + A4 — FK workspace_id + CASCADE] */ );

      -- =======================================================================
      -- 7. intel_documents + intel_fts  (moved from src/intel/store.ts:21)
      -- =======================================================================
      CREATE TABLE intel_documents ( /* [A1 + A4] */ );
      CREATE VIRTUAL TABLE intel_fts USING fts5( /* ... */ );
      CREATE TRIGGER intel_ai AFTER INSERT ON intel_documents BEGIN ... END;
      CREATE TRIGGER intel_ad AFTER DELETE ON intel_documents BEGIN ... END;
      CREATE TRIGGER intel_au AFTER UPDATE ON intel_documents BEGIN ... END;

      -- =======================================================================
      -- 8. A5 side-tables (e.g. finding_costs) — extracted normalisations
      -- =======================================================================
      -- [A5 owns additional CREATE TABLEs here; A1 names them; A4 constrains them]
    `);
  },
};
```

### 5.2 `initDb()` pseudocode for the backup branch (file:line anchor = `src/store.ts:119`)

```ts
// src/store.ts — additions marked NEW
import fs from "node:fs";

export interface InitDbOpts {
  /** Injected clock for deterministic tests. Defaults to () => new Date(). */
  now?: () => Date;
  /** Called on successful schema reset. Tests spy on this; prod wires the UI. */
  onReset?: (info: { oldVersion: number; backupPath: string }) => void;
}

export function initDb(dbPath: string, opts?: InitDbOpts): Database.Database {
  let db = openWithPragmas(dbPath);  // journal_mode=WAL, busy_timeout, synchronous, foreign_keys=ON

  const state = inspectSchemaState(db);
  if (state.kind === "corrupt") {
    db.close();
    throw new SchemaStateError(`DB at ${dbPath} is in a corrupt state: ${state.reason}`);
  }
  if (state.kind === "legacy-pre-v100") {
    const now = (opts?.now ?? (() => new Date()))();
    const backupPath = computeBackupPath(dbPath, state.version, now);

    // Acquire advisory lock to serialise concurrent resets
    const lockPath = dbPath + ".reset-lock";
    acquireResetLock(lockPath);  // throws on timeout; holds for duration of the reset
    try {
      // Re-check under lock (another process may have just reset)
      const reverified = inspectSchemaState(db);
      if (reverified.kind === "legacy-pre-v100") {
        db.close();
        const actualBackup = renameWithCollisionSuffix(dbPath, backupPath);
        (opts?.onReset ?? defaultResetLogger)({ oldVersion: state.version, backupPath: actualBackup });
        db = openWithPragmas(dbPath);  // fresh DB at original path
      } else {
        // Concurrent reset finished between first inspect and lock; nothing to do.
      }
    } finally {
      releaseResetLock(lockPath);
    }
  }

  // state.kind === "fresh" or "already-v100" — or legacy, now reset.
  runMigrations(db, allMigrations);
  db.pragma("wal_checkpoint(TRUNCATE)");
  return db;
}

// --- new helpers (all READ-ONLY of the filesystem except renameWithCollisionSuffix) ---

function openWithPragmas(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");
  return db;
}

function tableExists(db: Database.Database, name: string): boolean {
  const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(name);
  return !!row;
}

function computeBackupPath(dbPath: string, oldVersion: number, now: Date): string {
  const ts = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "");
  return `${dbPath}.bak-v${oldVersion}-${ts}`;
}

function renameWithCollisionSuffix(src: string, dst: string, maxRetries = 10): string {
  /* see 2.6 above */
}

function acquireResetLock(lockPath: string, timeoutMs = 30_000): void {
  /* fs.writeFileSync with flag 'wx'; on EEXIST, poll until file is removed or timeout */
}

function releaseResetLock(lockPath: string): void {
  try { fs.unlinkSync(lockPath); } catch { /* already gone */ }
}

function defaultResetLogger(info: { oldVersion: number; backupPath: string }): void {
  // Routes through the Ink plain-renderer to respect the UI contract in CLAUDE.md.
  getPlainRenderer().notice(
    `kuzushi: schema reset v${info.oldVersion} \u2192 v100; backup at ${info.backupPath}`,
  );
}
```

### 5.3 Test skeleton for `tests/migrations/schema-reset.test.ts`

```ts
import { describe, it, expect } from "vitest";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { initDb } from "../../src/store.js";

describe("v100 schema reset", () => {
  it("leaves a fresh DB alone (no backup created)", () => { /* ... */ });

  it("renames a legacy v25 DB and applies v100 to a fresh file", () => {
    const tmp = mktempDir();
    const dbPath = path.join(tmp, "index.sqlite3");
    seedLegacyV25Db(dbPath);  // run migrations 1..25 against a fresh DB via legacy runner

    const resets: unknown[] = [];
    const db = initDb(dbPath, { now: () => new Date("2026-04-16T14:23:07Z"), onReset: (i) => resets.push(i) });

    // Backup exists next to the DB
    const backup = path.join(tmp, "index.sqlite3.bak-v25-20260416T142307");
    expect(fs.existsSync(backup)).toBe(true);

    // New DB has only v100
    const rows = db.prepare("SELECT version FROM schema_version").all();
    expect(rows).toEqual([{ version: 100 }]);

    // Reset logger was called
    expect(resets).toHaveLength(1);
  });

  it("is a no-op on an already-v100 DB", () => { /* ... */ });

  it("throws on a corrupt DB (schema_version > 100)", () => { /* ... */ });

  it("handles concurrent resets via advisory lock", () => { /* spawn two workers, assert one backup */ });

  it("refuses to run on a readonly filesystem", () => { /* chmod 0o444; expect ReadOnlyDbError */ });

  it("resolves backup collisions with a numeric suffix", () => { /* pre-place the target; assert -1 */ });
});
```

---

## Verification checklist (self-audit against the brief)

- [x] Every migration 001–025 has an audit entry (§1 table).
- [x] The reset design answers fresh DB (§2.3 row 1), old DB (§2.3 row 3 + §2.2), already-reset DB (§2.3 row 2), corrupt DB (§2.3 row 4 + §5.2), concurrent processes (§2.5), readonly FS (§2.6).
- [x] Style guide is 15 rules (§3), each with a one-line example.
- [x] Cross-cutting observations specifically name A1/A4/A5 reservation points (§4).
- [x] Skeleton of `100_schema_reset.ts` included (§5.1).
- [x] `initDb()` pseudocode for the backup branch included (§5.2).
- [x] READ-ONLY on code; only write target was `/workspaces/Kuzushi/docs/data-model/03-migration-hygiene.md`.
