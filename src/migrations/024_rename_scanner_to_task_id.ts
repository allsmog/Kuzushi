import type { Migration } from "./types.js";

/**
 * Rename the legacy `scanner` column to `task_id`.
 *
 * Migration 002 was originally written to add a `scanner` column, then later
 * changed (same version number) to add `task_id` instead.  Databases created
 * before the rename have `scanner` but not `task_id`, while migration 002 is
 * already recorded as applied — so the new column never gets created.
 *
 * This migration detects the stale state and renames the column in-place
 * (requires SQLite ≥ 3.25, shipped with Node 22+).
 */
export const migration024: Migration = {
  version: 24,
  name: "rename_scanner_to_task_id",
  up(db) {
    const columns = new Set(
      (db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>)
        .map((c) => c.name),
    );

    if (columns.has("scanner") && !columns.has("task_id")) {
      db.exec("ALTER TABLE findings RENAME COLUMN scanner TO task_id");
      db.exec("DROP INDEX IF EXISTS idx_scanner");
      db.exec("CREATE INDEX IF NOT EXISTS idx_task_id ON findings(task_id)");
    }
  },
};
