import type { Migration } from "./types.js";

/**
 * v108: per-run scan findings buffer for the SQLite-backed
 * `ScanFindingsStore` (issue #33 follow-up).
 *
 * The orchestrator's `state.scanFindings` is a memory-bounded buffer of raw
 * findings accumulated across an entire pipeline run. For very large monorepo
 * scans (10k+ raw findings) that buffer dominates the heap, and call sites
 * that just need a count or fingerprint set still walk the full collection.
 *
 * `SqliteScanFindingsStore` cursor-pages findings via `stmt.iterate()`. This
 * migration provides its on-disk shape:
 *
 *   scan_findings(run_id, ordinal, finding_json)
 *
 * `(run_id, ordinal)` is a composite primary key — the ordinal preserves
 * insertion order across `add` / `addAll` / `replace`, so `iterate()` returns
 * the same sequence the in-memory implementation would. `finding_json` holds
 * the serialized `Finding` payload; the store is intentionally schema-light
 * because findings flow through `coerceFindings` on read anyway.
 *
 * Idempotent: skips if the table already exists.
 */
export const migration108: Migration = {
  version: 108,
  name: "scan_findings",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS scan_findings (
        run_id        TEXT NOT NULL,
        ordinal       INTEGER NOT NULL,
        finding_json  TEXT NOT NULL,
        PRIMARY KEY (run_id, ordinal)
      ) WITHOUT ROWID;

      CREATE INDEX IF NOT EXISTS idx_scan_findings_run_id
        ON scan_findings(run_id);
    `);
  },
};
