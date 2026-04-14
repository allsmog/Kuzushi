import type Database from "better-sqlite3";
import type { Migration } from "./types.js";

/**
 * Ensure the `schema_version` bookkeeping table exists.
 */
function ensureSchemaVersionTable(db: Database.Database): void {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version    INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      applied_at TEXT NOT NULL
    )
  `).run();
}

/**
 * Return the set of migration versions that have already been applied.
 */
function getAppliedVersions(db: Database.Database): Set<number> {
  const rows = db.prepare("SELECT version FROM schema_version").all() as Array<{ version: number }>;
  return new Set(rows.map((r) => r.version));
}

/**
 * Detect whether this is a legacy database that was set up by the old ad-hoc
 * `initDb()` before migrations existed. If so, mark all migrations up to the
 * detected state as already applied so they are not re-run.
 *
 * Detection heuristic: the `findings` table exists but the `schema_version`
 * table was just freshly created (empty).
 */
function detectAndMarkLegacyDatabase(
  db: Database.Database,
  _migrations: Migration[],
): Set<number> {
  const applied = getAppliedVersions(db);
  if (applied.size > 0) {
    // Already a migration-managed database
    return applied;
  }

  // Check if the findings table exists (legacy indicator)
  const findingsTable = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'findings'",
  ).get() as { name: string } | undefined;

  if (!findingsTable) {
    // Brand-new database — no legacy state to account for
    return applied;
  }

  // This is a legacy database. Figure out how far the schema has evolved
  // by inspecting what columns/tables exist, then mark matching migrations.
  const findingsColumns = new Set(
    (db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>)
      .map((c) => c.name),
  );

  const pipelineTable = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'",
  ).get() as { name: string } | undefined;

  const calibrationTable = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'calibration_weights'",
  ).get() as { name: string } | undefined;

  const trajectoriesTable = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'trajectories'",
  ).get() as { name: string } | undefined;
  const dynamicAnalysisRunsTable = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'dynamic_analysis_runs'",
  ).get() as { name: string } | undefined;
  const patchResultsTable = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'patch_results'",
  ).get() as { name: string } | undefined;

  const now = new Date().toISOString();
  const insertVersion = db.prepare(
    "INSERT OR IGNORE INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
  );

  // Migration 001: findings + pipeline_runs base tables
  // If findings exists, migration 001 is effectively applied
  insertVersion.run(1, "initial_schema", now);
  applied.add(1);

  // Migration 002: task_id column
  if (findingsColumns.has("task_id")) {
    insertVersion.run(2, "add_task_id_column", now);
    applied.add(2);
  }

  // Migration 003: triage_cost_usd
  if (findingsColumns.has("triage_cost_usd")) {
    insertVersion.run(3, "add_triage_cost_column", now);
    applied.add(3);
  }

  // Migration 004: triage_details_json
  if (findingsColumns.has("triage_details_json")) {
    insertVersion.run(4, "add_triage_details_column", now);
    applied.add(4);
  }

  // Migration 005: verification columns
  if (findingsColumns.has("verify_exploitable")) {
    insertVersion.run(5, "add_verification_columns", now);
    applied.add(5);
  }

  // Migration 006: poc harness columns
  if (findingsColumns.has("poc_harness_path")) {
    insertVersion.run(6, "add_poc_harness_columns", now);
    applied.add(6);
  }

  // Migration 007: poc execution columns
  if (findingsColumns.has("poc_run_exit_code")) {
    insertVersion.run(7, "add_poc_execution_columns", now);
    applied.add(7);
  }

  // Migration 008: pipeline_runs status constraint expansion
  if (pipelineTable) {
    const tableSql = db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'",
    ).get() as { sql?: string } | undefined;

    if (tableSql?.sql?.includes("'verifying'") && tableSql?.sql?.includes("'poc-harnessing'")) {
      insertVersion.run(8, "pipeline_runs_status_values", now);
      applied.add(8);
    }
  }

  // Migration 009: pipeline_runs context_json
  if (pipelineTable) {
    const prColumns = new Set(
      (db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>)
        .map((c) => c.name),
    );
    if (prColumns.has("context_json")) {
      insertVersion.run(9, "add_pipeline_runs_context", now);
      applied.add(9);
    }
  }

  // Migration 010: calibration schema
  if (calibrationTable && findingsColumns.has("calibrated_confidence")) {
    insertVersion.run(10, "add_calibration_schema", now);
    applied.add(10);
  }

  // Migration 011: trajectories table
  if (trajectoriesTable) {
    insertVersion.run(11, "add_trajectories_table", now);
    applied.add(11);
  }

  // Migration 016: structured finding evidence columns
  if (findingsColumns.has("taint_path_json") && findingsColumns.has("proof_state") && findingsColumns.has("engine_provenance_json")) {
    insertVersion.run(16, "add_structured_finding_evidence", now);
    applied.add(16);
  }

  // Migration 017: dynamic + patch persistence
  if (findingsColumns.has("finding_metadata_json") && dynamicAnalysisRunsTable && patchResultsTable) {
    insertVersion.run(17, "add_dynamic_and_patch_persistence", now);
    applied.add(17);
  }

  return applied;
}

/**
 * Run all pending migrations against the given database.
 *
 * - Creates the `schema_version` tracking table if absent.
 * - Detects legacy databases and marks already-applied migrations.
 * - Runs each unapplied migration inside its own transaction.
 *
 * @returns List of migrations that were newly applied during this call.
 */
export function runMigrations(
  db: Database.Database,
  migrations: Migration[],
): Array<{ version: number; name: string }> {
  ensureSchemaVersionTable(db);

  // Sort migrations by version to guarantee execution order
  const sorted = [...migrations].sort((a, b) => a.version - b.version);

  // Handle backwards compatibility with pre-migration databases
  const applied = detectAndMarkLegacyDatabase(db, sorted);

  const newlyApplied: Array<{ version: number; name: string }> = [];

  for (const migration of sorted) {
    if (applied.has(migration.version)) {
      continue;
    }

    // Run each migration in its own transaction
    const runOne = db.transaction(() => {
      migration.up(db);

      db.prepare(
        "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
      ).run(migration.version, migration.name, new Date().toISOString());
    });

    runOne();
    newlyApplied.push({ version: migration.version, name: migration.name });
  }

  return newlyApplied;
}
