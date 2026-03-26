import type { Migration } from "./types.js";

export const migration021: Migration = {
  version: 21,
  name: "add_incremental_scanning_support",
  up(db) {
    const columns = new Set(
      (db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>)
        .map((c) => c.name),
    );
    if (!columns.has("head_ref")) {
      db.exec("ALTER TABLE pipeline_runs ADD COLUMN head_ref TEXT");
    }

    db.exec("CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path)");
  },
};
