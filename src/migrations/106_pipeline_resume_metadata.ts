import type { Migration } from "./types.js";

/**
 * Add module/tool origin metadata to pipeline runs and expand the run status
 * constraint with `interrupted`, which represents unfinished work with a
 * usable checkpoint.
 */
export const migration106: Migration = {
  version: 106,
  name: "pipeline_resume_metadata",
  up(db) {
    const tableSql = db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'")
      .get() as { sql?: string } | undefined;

    if (!tableSql?.sql) return;

    const columns = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
    const colNames = columns.map((c) => c.name);
    const hasOriginColumns = ["module_id", "tool_name", "resume_label"].every((name) =>
      colNames.includes(name),
    );
    if (hasOriginColumns && tableSql.sql.includes("'interrupted'")) {
      return;
    }

    db.exec("DROP TABLE IF EXISTS pipeline_runs_v106");
    db.exec(`
      CREATE TABLE pipeline_runs_v106 (
        run_id          TEXT PRIMARY KEY,
        repo            TEXT NOT NULL,
        module_id       TEXT,
        tool_name       TEXT,
        resume_label    TEXT,
        started_at      TEXT NOT NULL,
        status          TEXT NOT NULL
                        CHECK (status IN ('scanning','triaging','verifying',
                                          'poc-harnessing','dynamic-analyzing',
                                          'interrupted','complete','error','aborted')),
        config_json     TEXT NOT NULL,
        scan_opts_json  TEXT NOT NULL,
        findings_json   TEXT,
        context_json    TEXT,
        total_cost_usd  REAL NOT NULL DEFAULT 0,
        completed_at    TEXT,
        metrics_json    TEXT,
        assertions_json TEXT,
        prompt_hash     TEXT,
        head_ref        TEXT,
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);

    const v106Columns = [
      "run_id",
      "repo",
      "module_id",
      "tool_name",
      "resume_label",
      "started_at",
      "status",
      "config_json",
      "scan_opts_json",
      "findings_json",
      "context_json",
      "total_cost_usd",
      "completed_at",
      "metrics_json",
      "assertions_json",
      "prompt_hash",
      "head_ref",
      "updated_at",
    ];
    const existingCols = v106Columns.filter((c) => colNames.includes(c));

    db.exec(`
      INSERT INTO pipeline_runs_v106 (${existingCols.join(", ")})
      SELECT ${existingCols.join(", ")}
      FROM pipeline_runs
    `);

    db.exec("DROP TABLE pipeline_runs");
    db.exec("ALTER TABLE pipeline_runs_v106 RENAME TO pipeline_runs");
    db.exec(
      "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status)",
    );
    db.exec(
      "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at ON pipeline_runs(started_at DESC)",
    );
  },
};
