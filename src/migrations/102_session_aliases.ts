/**
 * Migration 102 — session aliases.
 *
 * Adds a nullable `alias` column to `sessions` so operators can assign
 * human-friendly names to live sessions (`sessions -n <id> acme-web`).
 * Mirrors msfconsole's `sessions -n`.
 *
 * The column is additive; existing rows get NULL which the rendering
 * layer treats as "no alias". No uniqueness constraint — aliases are
 * scoped by convention, not enforced — so an operator can reuse an
 * alias across workspaces without a UX cliff.
 *
 * Rollback: Kuzushi migrations are forward-only. Restore a pre-upgrade DB
 * backup if this needs to be reverted after release.
 */

import type { Migration } from "./types.js";

export const migration102: Migration = {
  version: 102,
  name: "session_aliases",
  up(db) {
    const columns = db.prepare("PRAGMA table_info(sessions)").all() as Array<{ name: string }>;
    if (!columns.some((column) => column.name === "alias")) {
      db.exec("ALTER TABLE sessions ADD COLUMN alias TEXT;");
    }
  },
};
