/**
 * Migration 103 — persisted schedules.
 *
 * The Scheduler (src/scheduler/core.ts) stores active schedules here so
 * they survive a shell restart. Schedules are intentionally workspace-
 * agnostic (an operator may want `every 24h: quick-scan` regardless of
 * the active workspace).
 *
 * Rollback: Kuzushi migrations are forward-only. Restore a pre-upgrade DB
 * backup if this needs to be reverted after release.
 */

import type { Migration } from "./types.js";

export const migration103: Migration = {
  version: 103,
  name: "schedules",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS schedules (
        label          TEXT PRIMARY KEY,
        interval_spec  TEXT NOT NULL,
        command        TEXT NOT NULL,
        last_fired_at  INTEGER,
        next_fire_at   INTEGER NOT NULL,
        created_at     TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  },
};
