import type { Migration } from "./types.js";

/** Add the trajectories table for cross-run learning. */
export const migration011: Migration = {
  version: 11,
  name: "add_trajectories_table",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS trajectories (
        id              TEXT PRIMARY KEY,
        rule_id         TEXT NOT NULL,
        cwes_json       TEXT NOT NULL,
        scanner         TEXT NOT NULL,
        verdict         TEXT NOT NULL,
        confidence      REAL NOT NULL,
        was_correct     INTEGER,
        steps_json      TEXT NOT NULL,
        summary         TEXT NOT NULL,
        repo            TEXT NOT NULL,
        fingerprint     TEXT,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_trajectories_rule_id ON trajectories(rule_id);
      CREATE INDEX IF NOT EXISTS idx_trajectories_was_correct ON trajectories(was_correct);
    `);
  },
};
