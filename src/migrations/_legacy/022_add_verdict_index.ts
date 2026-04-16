import type { Migration } from "./types.js";

export const migration022: Migration = {
  version: 22,
  name: "add_verdict_index",
  up(db) {
    db.exec(`CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict)`);
  },
};
