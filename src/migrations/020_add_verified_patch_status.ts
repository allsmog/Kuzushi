import type { Migration } from "./types.js";

/**
 * Extend patch_results status CHECK constraint to include VERIFIED.
 * SQLite does not support ALTER CHECK, so we recreate the table.
 */
export const migration020: Migration = {
  version: 20,
  name: "add_verified_patch_status",
  up(db) {
    db.exec(`ALTER TABLE patch_results RENAME TO patch_results_old`);

    db.exec(`
      CREATE TABLE patch_results (
        patch_run_id    TEXT PRIMARY KEY,
        fingerprint     TEXT NOT NULL,
        repo            TEXT NOT NULL,
        diff            TEXT,
        status          TEXT NOT NULL CHECK (status IN ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE','TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')),
        iterations      INTEGER NOT NULL DEFAULT 1,
        build_command   TEXT,
        test_command    TEXT,
        worktree_path   TEXT,
        cost_usd        REAL,
        validator_log   TEXT,
        history_json    TEXT NOT NULL,
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);

    db.exec(`INSERT INTO patch_results SELECT * FROM patch_results_old`);
    db.exec(`DROP TABLE patch_results_old`);

    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_patch_results_fingerprint
        ON patch_results(fingerprint, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_patch_results_repo_status
        ON patch_results(repo, status)
    `);
  },
};
