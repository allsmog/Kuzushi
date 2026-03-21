import type { Migration } from "./types.js";

/**
 * Add persistence for generic finding metadata, dynamic analysis runs, and patch results.
 */
export const migration017: Migration = {
  version: 17,
  name: "add_dynamic_and_patch_persistence",
  up(db) {
    const findingColumns = new Set(
      (db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>)
        .map((column) => column.name),
    );

    if (!findingColumns.has("finding_metadata_json")) {
      db.exec("ALTER TABLE findings ADD COLUMN finding_metadata_json TEXT");
    }

    db.exec(`
      CREATE TABLE IF NOT EXISTS dynamic_analysis_runs (
        dynamic_run_id        TEXT PRIMARY KEY,
        pipeline_run_id       TEXT,
        fingerprint           TEXT NOT NULL,
        repo                  TEXT NOT NULL,
        status                TEXT NOT NULL CHECK (status IN ('confirmed','interesting','rejected','error')),
        score                 REAL NOT NULL DEFAULT 0,
        proof_value           REAL NOT NULL DEFAULT 0,
        language              TEXT,
        harness_path          TEXT,
        harness_language      TEXT,
        seed_inputs_json      TEXT,
        coverage_mode         TEXT,
        coverage_summary      TEXT,
        execution_exit_code   INTEGER,
        execution_stdout      TEXT,
        execution_stderr      TEXT,
        execution_verdict     TEXT,
        execution_duration_ms INTEGER,
        iterations            INTEGER NOT NULL DEFAULT 1,
        cost_usd              REAL,
        metadata_json         TEXT,
        created_at            TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_dynamic_analysis_runs_fingerprint
        ON dynamic_analysis_runs(fingerprint, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_dynamic_analysis_runs_repo_status
        ON dynamic_analysis_runs(repo, status);

      CREATE TABLE IF NOT EXISTS patch_results (
        patch_run_id    TEXT PRIMARY KEY,
        fingerprint     TEXT NOT NULL,
        repo            TEXT NOT NULL,
        diff            TEXT,
        status          TEXT NOT NULL CHECK (status IN ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE','TESTS_FAILED','SOUND','UNKNOWN')),
        iterations      INTEGER NOT NULL DEFAULT 1,
        build_command   TEXT,
        test_command    TEXT,
        worktree_path   TEXT,
        cost_usd        REAL,
        validator_log   TEXT,
        history_json    TEXT NOT NULL,
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_patch_results_fingerprint
        ON patch_results(fingerprint, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_patch_results_repo_status
        ON patch_results(repo, status);
    `);
  },
};
