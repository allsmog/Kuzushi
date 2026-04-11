import type { Migration } from "./types.js";

/**
 * Recreate pipeline_runs to expand the status CHECK constraint to include
 * 'verifying' and 'poc-harnessing', and ensure context_json column exists.
 *
 * This mirrors the legacy `ensurePipelineRunsStatusValues()` table recreation.
 */
export const migration008: Migration = {
  version: 8,
  name: "pipeline_runs_status_values",
  up(db) {
    // Check whether the table already has the expanded CHECK constraint
    const tableSql = db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'",
    ).get() as { sql?: string } | undefined;

    if (!tableSql?.sql) {
      // Table doesn't exist — create it fresh with all status values
      db.exec(`
        CREATE TABLE pipeline_runs (
          run_id         TEXT PRIMARY KEY,
          repo           TEXT NOT NULL,
          started_at     TEXT NOT NULL,
          status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','verifying','poc-harnessing','dynamic-analyzing','complete','error','aborted')),
          config_json    TEXT NOT NULL,
          scan_opts_json TEXT NOT NULL,
          findings_json  TEXT,
          context_json   TEXT,
          total_cost_usd REAL NOT NULL DEFAULT 0,
          completed_at   TEXT,
          updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status);
        CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at  ON pipeline_runs(started_at DESC);
      `);
      return;
    }

    if (tableSql.sql.includes("'verifying'") && tableSql.sql.includes("'poc-harnessing'")) {
      // Already has the expanded values — nothing to do
      return;
    }

    // Determine whether context_json exists in old table (to copy it)
    const contextSelect = tableSql.sql.includes("context_json") ? "context_json" : "NULL";

    db.exec("DROP TABLE IF EXISTS pipeline_runs_v2");
    db.exec(`
      CREATE TABLE pipeline_runs_v2 (
        run_id         TEXT PRIMARY KEY,
        repo           TEXT NOT NULL,
        started_at     TEXT NOT NULL,
        status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','verifying','poc-harnessing','dynamic-analyzing','complete','error','aborted')),
        config_json    TEXT NOT NULL,
        scan_opts_json TEXT NOT NULL,
        findings_json  TEXT,
        context_json   TEXT,
        total_cost_usd REAL NOT NULL DEFAULT 0,
        completed_at   TEXT,
        updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);

    db.exec(`
      INSERT INTO pipeline_runs_v2 (
        run_id, repo, started_at, status, config_json, scan_opts_json,
        findings_json, context_json, total_cost_usd, completed_at, updated_at
      )
      SELECT
        run_id, repo, started_at, status, config_json, scan_opts_json,
        findings_json, ${contextSelect}, total_cost_usd, completed_at, updated_at
      FROM pipeline_runs
    `);

    db.exec("DROP TABLE pipeline_runs");
    db.exec("ALTER TABLE pipeline_runs_v2 RENAME TO pipeline_runs");
    db.exec("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status)");
    db.exec("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at ON pipeline_runs(started_at DESC)");
  },
};
