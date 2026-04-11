import type { Migration } from "./types.js";

/**
 * Expand the pipeline_runs status CHECK constraint to include
 * 'dynamic-analyzing' and 'aborted'.
 */
export const migration023: Migration = {
  version: 23,
  name: "expand_pipeline_status_constraint",
  up(db) {
    const tableSql = db.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'",
    ).get() as { sql?: string } | undefined;

    if (!tableSql?.sql) {
      return;
    }

    // Already has the expanded values — nothing to do
    if (tableSql.sql.includes("'dynamic-analyzing'") && tableSql.sql.includes("'aborted'")) {
      return;
    }

    // Discover existing columns so we copy all of them
    const columns = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
    const colNames = columns.map((c) => c.name);

    db.exec("DROP TABLE IF EXISTS pipeline_runs_v3");
    db.exec(`
      CREATE TABLE pipeline_runs_v3 (
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
        updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
        metrics_json   TEXT,
        assertions_json TEXT,
        prompt_hash    TEXT,
        head_ref       TEXT
      )
    `);

    // Copy only columns that exist in the source table
    const v3Columns = [
      "run_id", "repo", "started_at", "status", "config_json", "scan_opts_json",
      "findings_json", "context_json", "total_cost_usd", "completed_at", "updated_at",
      "metrics_json", "assertions_json", "prompt_hash", "head_ref",
    ];
    const existingCols = v3Columns.filter((c) => colNames.includes(c));

    db.exec(`
      INSERT INTO pipeline_runs_v3 (${existingCols.join(", ")})
      SELECT ${existingCols.join(", ")}
      FROM pipeline_runs
    `);

    db.exec("DROP TABLE pipeline_runs");
    db.exec("ALTER TABLE pipeline_runs_v3 RENAME TO pipeline_runs");
    db.exec("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status)");
    db.exec("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at ON pipeline_runs(started_at DESC)");
  },
};
