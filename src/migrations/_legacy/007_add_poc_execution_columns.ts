import type { Migration } from "./types.js";

/** Add PoC execution result columns to findings. */
export const migration007: Migration = {
  version: 7,
  name: "add_poc_execution_columns",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((c) => c.name));

    const additions: Array<[string, string]> = [
      ["poc_run_exit_code", "INTEGER"],
      ["poc_run_stdout", "TEXT"],
      ["poc_run_stderr", "TEXT"],
      ["poc_run_verdict", "TEXT"],
      ["poc_run_duration_ms", "REAL"],
    ];

    for (const [col, typ] of additions) {
      if (!names.has(col)) {
        db.exec(`ALTER TABLE findings ADD COLUMN ${col} ${typ}`);
      }
    }
  },
};
