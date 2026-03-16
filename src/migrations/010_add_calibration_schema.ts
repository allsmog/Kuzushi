import type { Migration } from "./types.js";

/** Add the calibration_weights table and calibration columns on findings. */
export const migration010: Migration = {
  version: 10,
  name: "add_calibration_schema",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS calibration_weights (
        step_type     TEXT NOT NULL,
        rule_family   TEXT NOT NULL,
        weight        REAL NOT NULL DEFAULT 1.0,
        sample_count  INTEGER NOT NULL DEFAULT 0,
        updated_at    TEXT NOT NULL,
        PRIMARY KEY (step_type, rule_family)
      )
    `);

    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((c) => c.name));

    if (!names.has("calibrated_confidence")) {
      db.exec("ALTER TABLE findings ADD COLUMN calibrated_confidence REAL");
    }
    if (!names.has("evidence_chain_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN evidence_chain_json TEXT");
    }
  },
};
