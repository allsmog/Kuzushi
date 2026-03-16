import type { Migration } from "./types.js";

/** Add metrics_json column to pipeline_runs. */
export const migration014: Migration = {
  version: 14,
  name: "add_metrics_column",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
    const hasMetrics = columns.some((column) => column.name === "metrics_json");
    if (!hasMetrics) {
      db.exec("ALTER TABLE pipeline_runs ADD COLUMN metrics_json TEXT");
    }
  },
};
