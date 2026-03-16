import type { Migration } from "./types.js";

/** Add composite_confidence and confidence_signals_json columns to findings. */
export const migration013: Migration = {
  version: 13,
  name: "add_composite_confidence_columns",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => column.name));

    if (!names.has("composite_confidence")) {
      db.exec("ALTER TABLE findings ADD COLUMN composite_confidence REAL");
    }
    if (!names.has("confidence_signals_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN confidence_signals_json TEXT");
    }
  },
};
