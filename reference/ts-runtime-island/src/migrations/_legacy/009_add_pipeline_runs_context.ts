import type { Migration } from "./types.js";

/** Add `context_json` column to pipeline_runs (if not already present from migration 008). */
export const migration009: Migration = {
  version: 9,
  name: "add_pipeline_runs_context",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === "context_json")) {
      db.exec("ALTER TABLE pipeline_runs ADD COLUMN context_json TEXT");
    }
  },
};
