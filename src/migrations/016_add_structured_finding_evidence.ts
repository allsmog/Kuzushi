import type { Migration } from "./types.js";

/**
 * Add structured evidence columns for findings.
 */
export const migration016: Migration = {
  version: 16,
  name: "add_structured_finding_evidence",
  up(db) {
    const columns = new Set(
      (db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>)
        .map((column) => column.name),
    );

    if (!columns.has("taint_path_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN taint_path_json TEXT");
    }
    if (!columns.has("proof_state")) {
      db.exec("ALTER TABLE findings ADD COLUMN proof_state TEXT");
    }
    if (!columns.has("engine_provenance_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN engine_provenance_json TEXT");
    }
  },
};
