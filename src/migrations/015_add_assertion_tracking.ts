import type { Migration } from "./types.js";

export const migration015: Migration = {
  version: 15,
  name: "add_assertion_tracking",
  up(db) {
    // Add new columns to pipeline_runs (idempotent check)
    const pipelineCols = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
    const pipelineColNames = new Set(pipelineCols.map((c) => c.name));

    if (!pipelineColNames.has("assertions_json")) {
      db.prepare("ALTER TABLE pipeline_runs ADD COLUMN assertions_json TEXT").run();
    }
    if (!pipelineColNames.has("prompt_hash")) {
      db.prepare("ALTER TABLE pipeline_runs ADD COLUMN prompt_hash TEXT").run();
    }

    // Create finding_assertions table and index using individual statements
    db.prepare(`
      CREATE TABLE IF NOT EXISTS finding_assertions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        assertion_name TEXT NOT NULL,
        passed INTEGER NOT NULL,
        score REAL NOT NULL,
        weight REAL NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();

    db.prepare(
      "CREATE INDEX IF NOT EXISTS idx_finding_assertions_run ON finding_assertions(run_id)"
    ).run();
  },
};
