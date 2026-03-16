import type { Migration } from "./types.js";

/** Add `triage_details_json` column to findings. */
export const migration004: Migration = {
  version: 4,
  name: "add_triage_details_column",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === "triage_details_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN triage_details_json TEXT");
    }
  },
};
