import type { Migration } from "./types.js";

/** Add PoC harness generation columns to findings. */
export const migration006: Migration = {
  version: 6,
  name: "add_poc_harness_columns",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((c) => c.name));

    const additions: Array<[string, string]> = [
      ["poc_harness_path", "TEXT"],
      ["poc_harness_language", "TEXT"],
      ["poc_harness_parsed", "INTEGER"],
      ["poc_harness_parse_error", "TEXT"],
      ["poc_harness_skipped", "INTEGER"],
      ["poc_harness_skip_reason", "TEXT"],
      ["poc_harness_cost_usd", "REAL"],
    ];

    for (const [col, typ] of additions) {
      if (!names.has(col)) {
        db.exec(`ALTER TABLE findings ADD COLUMN ${col} ${typ}`);
      }
    }
  },
};
