import type { Migration } from "./types.js";

/** Add the `scanner` column to findings (originally defaulted to 'semgrep'). */
export const migration002: Migration = {
  version: 2,
  name: "add_scanner_column",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    if (!columns.some((c) => c.name === "scanner")) {
      db.exec("ALTER TABLE findings ADD COLUMN scanner TEXT NOT NULL DEFAULT 'semgrep'");
    }

    // Ensure the index exists regardless
    db.exec("CREATE INDEX IF NOT EXISTS idx_scanner ON findings(scanner)");
  },
};
