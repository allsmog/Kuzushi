import type { Migration } from "./types.js";

export const migration018: Migration = {
  version: 18,
  name: "add_crypto_behavioral_runs",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS crypto_behavioral_runs (
        run_id                TEXT PRIMARY KEY,
        pipeline_run_id       TEXT,
        fingerprint           TEXT NOT NULL,
        repo                  TEXT NOT NULL,
        test_type             TEXT NOT NULL,
        verdict               TEXT NOT NULL,
        harness_path          TEXT,
        harness_language      TEXT,
        execution_exit_code   INTEGER,
        execution_verdict     TEXT,
        execution_stdout      TEXT,
        execution_stderr      TEXT,
        execution_duration_ms INTEGER,
        t_statistic           REAL,
        p_value               REAL,
        mean_a_ns             REAL,
        mean_b_ns             REAL,
        timing_iterations     INTEGER,
        observed_behavior     TEXT,
        expected_behavior     TEXT,
        algorithm_confirmed   TEXT,
        key_length_bits       INTEGER,
        cost_usd              REAL,
        metadata_json         TEXT,
        created_at            TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_crypto_behavioral_fingerprint
        ON crypto_behavioral_runs(fingerprint, created_at DESC);
    `);
  },
};
