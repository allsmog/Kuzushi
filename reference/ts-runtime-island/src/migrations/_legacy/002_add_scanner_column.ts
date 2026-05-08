import type { Migration } from "./types.js";

/** Add the `task_id` column to findings (defaulted to 'semgrep'). */
export const migration002: Migration = {
  version: 2,
  name: "add_task_id_column",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === "task_id")) {
      db.exec("ALTER TABLE findings ADD COLUMN task_id TEXT NOT NULL DEFAULT 'semgrep'");
    }

    // Ensure the index exists regardless
    db.exec("CREATE INDEX IF NOT EXISTS idx_task_id ON findings(task_id)");
  },
};
