import type { Migration } from "./types.js";

/**
 * Add `branch` and `pr_number` columns to `pipeline_runs` so a single
 * findings.sqlite3 across many runs can be filtered by which branch or
 * PR produced each run.
 *
 * Field-test issue #44. Companion to existing `head_ref` column which
 * stores the commit SHA at scan time — this adds the human-friendly
 * branch + PR identifiers that `kuzushi runs list` / `inspect` /
 * future diff-aware features will key on.
 *
 * Idempotent: skips if columns already exist.
 */
export const migration107: Migration = {
  version: 107,
  name: "pipeline_runs_branch_pr",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
    const colNames = new Set(columns.map((c) => c.name));

    if (!colNames.has("branch")) {
      db.exec("ALTER TABLE pipeline_runs ADD COLUMN branch TEXT");
    }
    if (!colNames.has("pr_number")) {
      db.exec("ALTER TABLE pipeline_runs ADD COLUMN pr_number INTEGER");
    }

    db.exec("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_branch ON pipeline_runs(branch)");
    db.exec("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_pr_number ON pipeline_runs(pr_number)");
  },
};
