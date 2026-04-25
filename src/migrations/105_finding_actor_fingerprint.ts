/**
 * Migration 105 — actor_fingerprint column on findings.
 *
 * Threads the per-actor fingerprint that `threat-hunt` stamps on each
 * `Finding` (see `src/scanners/types.ts`) through to the persisted store
 * so the v3 `ActorTranscriptView` can synthesize ★ Finding rows for
 * completed and replayed runs — not just live ones.
 *
 * Backfill: existing rows get NULL, which the UI treats as "unscoped".
 *
 * Rollback: Kuzushi migrations are forward-only. Restore a pre-upgrade
 * DB backup if this needs to be reverted after release.
 */

import type Database from "better-sqlite3";
import type { Migration } from "./types.js";

/**
 * Replay-safe column probe. SQLite's `ALTER TABLE ADD COLUMN` is not
 * idempotent — running it twice raises `duplicate column name`. The
 * runner's replay-safety contract (see migration 102/103/104 patterns
 * and the test at `tests/migrations/schema-reset.test.ts`) requires
 * each migration to be safely re-applicable when its `schema_version`
 * row is missing. We probe `pragma_table_info` first.
 */
function hasColumn(db: Database.Database, table: string, column: string): boolean {
  const rows = db
    .prepare("SELECT name FROM pragma_table_info(?) WHERE name = ?")
    .all(table, column) as Array<{ name: string }>;
  return rows.length > 0;
}

export const migration105: Migration = {
  version: 105,
  name: "finding_actor_fingerprint",
  up(db) {
    if (!hasColumn(db, "findings", "actor_fingerprint")) {
      db.exec(`ALTER TABLE findings ADD COLUMN actor_fingerprint TEXT`);
    }
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_findings_actor_fingerprint
        ON findings(actor_fingerprint)
        WHERE actor_fingerprint IS NOT NULL
    `);
  },
};
