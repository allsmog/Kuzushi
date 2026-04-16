import type { Migration } from "./types.js";

/**
 * Initial schema: creates the findings and pipeline_runs tables with their
 * base columns and indexes. Uses IF NOT EXISTS so it is safe to run against
 * a database that was created by the legacy ad-hoc setup.
 */
export const migration001: Migration = {
  version: 1,
  name: "initial_schema",
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        fingerprint        TEXT PRIMARY KEY,
        repo               TEXT NOT NULL,
        ref                TEXT NOT NULL,
        rule_id            TEXT NOT NULL,
        file_path          TEXT NOT NULL,
        start_line         INTEGER NOT NULL,
        severity           TEXT NOT NULL,
        message            TEXT NOT NULL,
        verdict            TEXT NOT NULL CHECK (verdict IN ('tp','fp','needs_review')),
        confidence         REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
        rationale          TEXT NOT NULL,
        verification_steps TEXT NOT NULL,
        fix_patch          TEXT,
        created_at         TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_repo_ref ON findings(repo, ref);
      CREATE INDEX IF NOT EXISTS idx_rule_id  ON findings(rule_id);

      CREATE TABLE IF NOT EXISTS pipeline_runs (
        run_id         TEXT PRIMARY KEY,
        repo           TEXT NOT NULL,
        started_at     TEXT NOT NULL,
        status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','complete','error')),
        config_json    TEXT NOT NULL,
        scan_opts_json TEXT NOT NULL,
        findings_json  TEXT,
        total_cost_usd REAL NOT NULL DEFAULT 0,
        completed_at   TEXT,
        updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status);
      CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at  ON pipeline_runs(started_at DESC);
    `);
  },
};
