import type { Migration } from "./types.js";

/**
 * Add workspace persistence tables.
 *
 * - `workspaces`: engagement workspaces with targets and metadata
 * - `workspace_snapshots`: serialized ContextSnapshot per workspace
 */
export const migration025: Migration = {
  version: 25,
  name: "add_workspaces_table",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS workspaces (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        targets_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        last_accessed_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS workspace_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
        snapshot_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_workspace_snapshots_workspace
        ON workspace_snapshots(workspace_id);
    `);
  },
};
