import type { Migration } from "./types.js";

/**
 * v100 schema reset.
 *
 * Consolidated replacement for legacy migrations 001–025. Runs against a
 * fresh database only; the reset branch in `initDb()` renames any legacy
 * DB to `findings.sqlite3.bak-v<old>-<UTC-ts>` before this migration runs.
 *
 * Changes vs migration 025 (rolled-up):
 *  - Drops ghost columns: findings.{calibrated_confidence, evidence_chain_json,
 *    composite_confidence, confidence_signals_json}; trajectories.{task_id,
 *    confidence, repo}; code_graph_{nodes,edges,paths}.run_id.
 *  - Fixes stale CHECK on findings.verdict to include 'by_design'.
 *  - Adds CHECK constraints on 15 enum-like TEXT columns + 6 boolean-as-INTEGER
 *    columns. See docs/data-model/04-constraints.md.
 *  - Adds 9 FKs with explicit ON DELETE (CASCADE for per-finding children;
 *    SET NULL for pipeline_run_id and trajectories.fingerprint).
 *  - Drops legacy `DEFAULT 'semgrep'` on findings.task_id (app always supplies).
 *
 * Not covered by this reset: `intel_documents` + `intel_fts` live in a
 * separate SQLite file (`.kuzushi/intel.sqlite3`) and are still created
 * ad-hoc via `createIntelTables()` in `src/intel/store.ts`. A future
 * refactor PR can give that DB its own migration trail.
 */
export const migration100: Migration = {
  version: 100,
  name: "schema_reset",
  up(db) {
    db.exec(`
      ----------------------------------------------------------------------
      -- findings
      ----------------------------------------------------------------------
      CREATE TABLE findings (
        fingerprint             TEXT PRIMARY KEY,
        task_id                 TEXT NOT NULL,
        repo                    TEXT NOT NULL,
        ref                     TEXT NOT NULL,
        rule_id                 TEXT NOT NULL,
        file_path               TEXT NOT NULL,
        start_line              INTEGER NOT NULL,
        severity                TEXT NOT NULL,
        message                 TEXT NOT NULL,
        verdict                 TEXT NOT NULL
                                CHECK (verdict IN ('tp','fp','needs_review','by_design')),
        confidence              REAL NOT NULL
                                CHECK (confidence >= 0 AND confidence <= 1),
        rationale               TEXT NOT NULL,
        verification_steps      TEXT NOT NULL,
        fix_patch               TEXT,
        adjusted_score          REAL,
        corroboration_json      TEXT,
        suppression_json        TEXT,
        triage_cost_usd         REAL,
        triage_details_json     TEXT,
        verify_exploitable      INTEGER
                                CHECK (verify_exploitable IS NULL OR verify_exploitable IN (0,1)),
        verify_poc_payload      TEXT,
        verify_poc_description  TEXT,
        verify_attack_vector    TEXT,
        verify_preconditions    TEXT,
        verify_confidence       REAL,
        verify_cost_usd         REAL,
        poc_harness_path        TEXT,
        poc_harness_language    TEXT,
        poc_harness_parsed      INTEGER
                                CHECK (poc_harness_parsed IS NULL OR poc_harness_parsed IN (0,1)),
        poc_harness_parse_error TEXT,
        poc_harness_skipped     INTEGER
                                CHECK (poc_harness_skipped IS NULL OR poc_harness_skipped IN (0,1)),
        poc_harness_skip_reason TEXT,
        poc_harness_cost_usd    REAL,
        poc_run_exit_code       INTEGER,
        poc_run_stdout          TEXT,
        poc_run_stderr          TEXT,
        poc_run_verdict         TEXT
                                CHECK (poc_run_verdict IS NULL
                                       OR poc_run_verdict IN ('PASS','FAIL','ERROR','TIMEOUT')),
        poc_run_duration_ms     REAL,
        taint_path_json         TEXT,
        proof_state             TEXT
                                CHECK (proof_state IS NULL
                                       OR proof_state IN ('symbolic_only','inconclusive',
                                                          'execution_attempted',
                                                          'execution_rejected',
                                                          'execution_confirmed')),
        engine_provenance_json  TEXT,
        finding_metadata_json   TEXT,
        created_at              TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at              TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_findings_repo_ref   ON findings(repo, ref);
      CREATE INDEX idx_findings_rule_id    ON findings(rule_id);
      CREATE INDEX idx_findings_file_path  ON findings(file_path);
      CREATE INDEX idx_findings_verdict    ON findings(verdict);
      CREATE INDEX idx_findings_task_id    ON findings(task_id);

      ----------------------------------------------------------------------
      -- pipeline_runs
      ----------------------------------------------------------------------
      CREATE TABLE pipeline_runs (
        run_id          TEXT PRIMARY KEY,
        repo            TEXT NOT NULL,
        module_id       TEXT,
        tool_name       TEXT,
        resume_label    TEXT,
        started_at      TEXT NOT NULL,
        status          TEXT NOT NULL
                        CHECK (status IN ('scanning','triaging','verifying',
                                          'poc-harnessing','dynamic-analyzing',
                                          'interrupted','complete','error','aborted')),
        config_json     TEXT NOT NULL,
        scan_opts_json  TEXT NOT NULL,
        findings_json   TEXT,
        context_json    TEXT,
        total_cost_usd  REAL NOT NULL DEFAULT 0,
        completed_at    TEXT,
        metrics_json    TEXT,
        assertions_json TEXT,
        prompt_hash     TEXT,
        head_ref        TEXT,
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_pipeline_runs_repo_status ON pipeline_runs(repo, status);
      CREATE INDEX idx_pipeline_runs_started_at  ON pipeline_runs(started_at DESC);

      ----------------------------------------------------------------------
      -- calibration_weights
      ----------------------------------------------------------------------
      CREATE TABLE calibration_weights (
        step_type    TEXT NOT NULL,
        rule_family  TEXT NOT NULL,
        weight       REAL NOT NULL DEFAULT 1.0,
        sample_count INTEGER NOT NULL DEFAULT 0,
        updated_at   TEXT NOT NULL,
        PRIMARY KEY (step_type, rule_family)
      );

      ----------------------------------------------------------------------
      -- trajectories
      ----------------------------------------------------------------------
      CREATE TABLE trajectories (
        id          TEXT PRIMARY KEY,
        rule_id     TEXT NOT NULL,
        cwes_json   TEXT NOT NULL,
        verdict     TEXT NOT NULL
                    CHECK (verdict IN ('tp','fp','needs_review','by_design')),
        was_correct INTEGER
                    CHECK (was_correct IS NULL OR was_correct IN (0,1)),
        steps_json  TEXT NOT NULL,
        summary     TEXT NOT NULL,
        fingerprint TEXT
                    REFERENCES findings(fingerprint) ON DELETE SET NULL,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
      );
      CREATE INDEX idx_trajectories_rule_id     ON trajectories(rule_id);
      CREATE INDEX idx_trajectories_was_correct ON trajectories(was_correct);

      ----------------------------------------------------------------------
      -- finding_assertions
      ----------------------------------------------------------------------
      CREATE TABLE finding_assertions (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id         TEXT NOT NULL
                       REFERENCES pipeline_runs(run_id) ON DELETE CASCADE,
        fingerprint    TEXT NOT NULL
                       REFERENCES findings(fingerprint) ON DELETE CASCADE,
        assertion_name TEXT NOT NULL,
        passed         INTEGER NOT NULL CHECK (passed IN (0,1)),
        score          REAL NOT NULL,
        weight         REAL NOT NULL,
        reason         TEXT NOT NULL,
        created_at     TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_finding_assertions_run ON finding_assertions(run_id);

      ----------------------------------------------------------------------
      -- dynamic_analysis_runs
      ----------------------------------------------------------------------
      CREATE TABLE dynamic_analysis_runs (
        dynamic_run_id        TEXT PRIMARY KEY,
        pipeline_run_id       TEXT
                              REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
        fingerprint           TEXT NOT NULL
                              REFERENCES findings(fingerprint) ON DELETE CASCADE,
        repo                  TEXT NOT NULL,
        status                TEXT NOT NULL
                              CHECK (status IN ('confirmed','interesting','rejected','error')),
        score                 REAL NOT NULL DEFAULT 0,
        proof_value           REAL NOT NULL DEFAULT 0,
        language              TEXT,
        harness_path          TEXT,
        harness_language      TEXT,
        seed_inputs_json      TEXT,
        coverage_mode         TEXT
                              CHECK (coverage_mode IS NULL
                                     OR coverage_mode IN ('none','node-v8','python-coverage')),
        coverage_summary      TEXT,
        execution_exit_code   INTEGER,
        execution_stdout      TEXT,
        execution_stderr      TEXT,
        execution_verdict     TEXT
                              CHECK (execution_verdict IS NULL
                                     OR execution_verdict IN ('PASS','FAIL','ERROR','TIMEOUT')),
        execution_duration_ms INTEGER,
        iterations            INTEGER NOT NULL DEFAULT 1,
        cost_usd              REAL,
        metadata_json         TEXT,
        created_at            TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_dynamic_analysis_runs_fingerprint
        ON dynamic_analysis_runs(fingerprint, created_at DESC);
      CREATE INDEX idx_dynamic_analysis_runs_repo_status
        ON dynamic_analysis_runs(repo, status);

      ----------------------------------------------------------------------
      -- patch_results
      ----------------------------------------------------------------------
      CREATE TABLE patch_results (
        patch_run_id  TEXT PRIMARY KEY,
        fingerprint   TEXT NOT NULL
                      REFERENCES findings(fingerprint) ON DELETE CASCADE,
        repo          TEXT NOT NULL,
        diff          TEXT,
        status        TEXT NOT NULL
                      CHECK (status IN ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE',
                                        'TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')),
        iterations    INTEGER NOT NULL DEFAULT 1,
        build_command TEXT,
        test_command  TEXT,
        worktree_path TEXT,
        cost_usd      REAL,
        validator_log TEXT,
        history_json  TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_patch_results_fingerprint
        ON patch_results(fingerprint, created_at DESC);
      CREATE INDEX idx_patch_results_repo_status
        ON patch_results(repo, status);

      ----------------------------------------------------------------------
      -- crypto_behavioral_runs
      ----------------------------------------------------------------------
      CREATE TABLE crypto_behavioral_runs (
        run_id                TEXT PRIMARY KEY,
        pipeline_run_id       TEXT
                              REFERENCES pipeline_runs(run_id) ON DELETE SET NULL,
        fingerprint           TEXT NOT NULL
                              REFERENCES findings(fingerprint) ON DELETE CASCADE,
        repo                  TEXT NOT NULL,
        test_type             TEXT NOT NULL
                              CHECK (test_type IN ('timing','ecb-mode','weak-hash',
                                                   'weak-prng','key-length','edge-case')),
        verdict               TEXT NOT NULL
                              CHECK (verdict IN ('vulnerable','secure','inconclusive','error')),
        harness_path          TEXT,
        harness_language      TEXT,
        execution_exit_code   INTEGER,
        execution_verdict     TEXT
                              CHECK (execution_verdict IS NULL
                                     OR execution_verdict IN ('PASS','FAIL','ERROR','TIMEOUT')),
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
      CREATE INDEX idx_crypto_behavioral_fingerprint
        ON crypto_behavioral_runs(fingerprint, created_at DESC);

      ----------------------------------------------------------------------
      -- code_graph_nodes
      ----------------------------------------------------------------------
      CREATE TABLE code_graph_nodes (
        node_id       TEXT PRIMARY KEY,
        repo          TEXT NOT NULL,
        file_path     TEXT NOT NULL,
        start_line    INTEGER NOT NULL,
        symbol        TEXT,
        node_kind     TEXT NOT NULL
                      CHECK (node_kind IN ('entry-http','entry-cli','entry-event',
                                           'entry-cron','entry-background',
                                           'middleware','controller','service',
                                           'data-access','external-call','sanitizer',
                                           'validator','transformer','unknown')),
        framework     TEXT,
        metadata_json TEXT,
        confidence    REAL NOT NULL DEFAULT 1.0,
        source        TEXT NOT NULL DEFAULT 'static'
                      CHECK (source IN ('static','llm','hybrid')),
        created_at    TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_cgn_repo ON code_graph_nodes(repo);
      CREATE INDEX idx_cgn_file ON code_graph_nodes(repo, file_path);
      CREATE INDEX idx_cgn_kind ON code_graph_nodes(repo, node_kind);

      ----------------------------------------------------------------------
      -- code_graph_edges
      ----------------------------------------------------------------------
      CREATE TABLE code_graph_edges (
        edge_id      TEXT PRIMARY KEY,
        repo         TEXT NOT NULL,
        from_node_id TEXT NOT NULL
                     REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
        to_node_id   TEXT NOT NULL
                     REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
        edge_kind    TEXT NOT NULL
                     CHECK (edge_kind IN ('calls','imports','middleware-chain',
                                          'callback','promise-chain','event-emit',
                                          'event-listen','di-inject','dynamic-dispatch',
                                          'data-flow','config-read','serialization')),
        data_label   TEXT,
        ordinal      INTEGER,
        confidence   REAL NOT NULL DEFAULT 1.0,
        source       TEXT NOT NULL DEFAULT 'static'
                     CHECK (source IN ('static','llm','hybrid')),
        created_at   TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_cge_repo ON code_graph_edges(repo);
      CREATE INDEX idx_cge_from ON code_graph_edges(from_node_id);
      CREATE INDEX idx_cge_to   ON code_graph_edges(to_node_id);

      ----------------------------------------------------------------------
      -- code_graph_paths
      ----------------------------------------------------------------------
      CREATE TABLE code_graph_paths (
        path_id         TEXT PRIMARY KEY,
        repo            TEXT NOT NULL,
        entry_node_id   TEXT NOT NULL
                        REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
        target_node_id  TEXT NOT NULL
                        REFERENCES code_graph_nodes(node_id) ON DELETE CASCADE,
        hop_count       INTEGER NOT NULL,
        path_node_ids   TEXT NOT NULL,
        path_edge_ids   TEXT NOT NULL,
        has_sanitizer   INTEGER NOT NULL DEFAULT 0
                        CHECK (has_sanitizer IN (0,1)),
        sanitizer_nodes TEXT,
        confidence      REAL NOT NULL,
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_cgp_entry  ON code_graph_paths(repo, entry_node_id);
      CREATE INDEX idx_cgp_target ON code_graph_paths(repo, target_node_id);

      ----------------------------------------------------------------------
      -- workspaces + workspace_snapshots
      ----------------------------------------------------------------------
      CREATE TABLE workspaces (
        id               TEXT PRIMARY KEY,
        name             TEXT NOT NULL UNIQUE,
        targets_json     TEXT NOT NULL DEFAULT '[]',
        created_at       TEXT NOT NULL,
        last_accessed_at TEXT NOT NULL,
        metadata_json    TEXT NOT NULL DEFAULT '{}',
        updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE workspace_snapshots (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        workspace_id  TEXT NOT NULL
                      REFERENCES workspaces(id) ON DELETE CASCADE,
        snapshot_json TEXT NOT NULL,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX idx_workspace_snapshots_workspace
        ON workspace_snapshots(workspace_id);
    `);
  },
};
