import type { Migration } from "./types.js";

/** Add exploitability-verification columns to findings. */
export const migration005: Migration = {
  version: 5,
  name: "add_verification_columns",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((c) => c.name));

    const additions: Array<[string, string]> = [
      ["verify_exploitable", "INTEGER"],
      ["verify_poc_payload", "TEXT"],
      ["verify_poc_description", "TEXT"],
      ["verify_attack_vector", "TEXT"],
      ["verify_preconditions", "TEXT"],
      ["verify_confidence", "REAL"],
      ["verify_cost_usd", "REAL"],
    ];

    for (const [col, typ] of additions) {
      if (!names.has(col)) {
        db.exec(`ALTER TABLE findings ADD COLUMN ${col} ${typ}`);
      }
    }
  },
};
