import type { Migration } from "./types.js";

/** Add persisted finding provenance columns for ranking/suppression metadata. */
export const migration012: Migration = {
  version: 12,
  name: "add_finding_provenance_columns",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => column.name));

    if (!names.has("adjusted_score")) {
      db.exec("ALTER TABLE findings ADD COLUMN adjusted_score REAL");
    }
    if (!names.has("corroboration_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN corroboration_json TEXT");
    }
    if (!names.has("suppression_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN suppression_json TEXT");
    }
  },
};
