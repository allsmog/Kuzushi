import type { Migration } from "./types.js";

/** Add `triage_cost_usd` column to findings. */
export const migration003: Migration = {
  version: 3,
  name: "add_triage_cost_column",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === "triage_cost_usd")) {
      db.exec("ALTER TABLE findings ADD COLUMN triage_cost_usd REAL");
    }
  },
};
