use super::*;
use crate::event_log::{EventEnvelope, EventKind, EventLog};

#[test]
fn projection_starts_at_zero_watermark() {
    let db = ProjectionDb::open_in_memory().unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, 0);
    assert_eq!(db.meta().unwrap().generation, 0);
}

#[test]
fn opening_legacy_projection_adds_verification_provenance_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table verification_events (
          event_hash text primary key,
          seq integer not null unique,
          stable_fp text not null,
          finding_id integer,
          identity_id text,
          proof_level integer not null,
          proof_verdict text not null,
          backend text not null,
          language text,
          harness_path text,
          crash_evidence text,
          duration_ms integer not null,
          cost_usd real not null,
          notes_json text not null,
          actor text not null,
          created_at text not null,
          payload_json text not null
        );
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    assert!(table_has_column(&conn, "verification_events", "verification_run_id").unwrap());
    assert!(table_has_column(&conn, "verification_events", "verified_scan_id").unwrap());
}

#[test]
fn opening_legacy_projection_adds_patch_provider_spend_column() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table patch_attempt_events (
          event_hash text primary key,
          seq integer not null unique,
          stable_fp text not null,
          fingerprint text not null,
          patch_run_id text not null,
          repo text not null,
          diff_object text,
          diff_size_bytes integer,
          status text not null,
          iterations integer not null,
          build_command text,
          test_command text,
          worktree_path text,
          cost_usd real,
          validator_log text,
          history_json text not null,
          actor text not null,
          created_at text not null,
          payload_json text not null
        );
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    assert!(table_has_column(&conn, "patch_attempt_events", "provider_spend_unresolved").unwrap());
}

#[test]
fn opening_legacy_projection_adds_patch_lifecycle_generation_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table patch_lifecycle_events (
          event_hash text primary key, seq integer, application_id text,
          stable_fp text, fingerprint text, patch_run_id text, target text,
          diff_hash text, base_commit text, touched_files_json text, state text,
          reverify_run_id text, detail text, actor text,
          applied_at text,
          application_started_at text, updated_at text, created_at text,
          payload_json text
        );
        create table patch_lifecycle_current (
          application_id text primary key, latest_seq integer, stable_fp text,
          fingerprint text, patch_run_id text, target text, diff_hash text,
          base_commit text, touched_files_json text, state text,
          reverify_run_id text, detail text, actor text,
          applied_at text,
          application_started_at text, updated_at text
        );
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    for table in ["patch_lifecycle_events", "patch_lifecycle_current"] {
        assert!(table_has_column(&conn, table, "finding_scan_id").unwrap());
    }
}

#[test]
fn legacy_patch_events_default_missing_unresolved_bit_to_false() {
    assert!(!projected_legacy_patch_spend_state(Some(125_000)));
    assert!(!projected_legacy_patch_spend_state(None));
}

#[test]
fn patch_event_replay_prefers_exact_cost_over_legacy_rounded_micros() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = log
        .append(
            EventKind::PatchAttemptRecorded,
            "exact-patch-cost",
            Some("patch-run".to_string()),
            None,
            serde_json::json!({
                "stableFp": "fp3_patch_exact",
                "fingerprint": "external-fp",
                "patchRunId": "patch-run",
                "repo": "/repo",
                "status": "SOUND",
                "iterations": 1,
                "costUsd": 0.000_000_4,
                "costUsdMicros": 0,
                "providerSpendUnresolved": true,
                "historyJson": "[]",
            }),
        )
        .unwrap();

    db.apply_event(&event).unwrap();

    let projected: (f64, bool) = db
        .conn
        .query_row(
            "select cost_usd, provider_spend_unresolved from patch_attempt_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(projected, (0.000_000_4, true));
}

fn projected_legacy_patch_spend_state(cost_usd_micros: Option<i64>) -> bool {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = log
        .append(
            EventKind::PatchAttemptRecorded,
            "legacy-patch",
            Some("patch-run".to_string()),
            None,
            serde_json::json!({
                "stableFp": "fp3_patch",
                "fingerprint": "external-fp",
                "patchRunId": "patch-run",
                "repo": "/repo",
                "status": "SOUND",
                "iterations": 1,
                "costUsdMicros": cost_usd_micros,
                "historyJson": "[]",
            }),
        )
        .unwrap();
    db.apply_event(&event).unwrap();
    db.conn
        .query_row(
            "select provider_spend_unresolved from patch_attempt_events",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn event_projection_commits_event_and_watermark_together() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_finding_event(&log);

    db.apply_event(&event).unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, event.seq);
    assert_eq!(projected_event_stable_fp(&db, event.seq), "fp3_test");
}

#[test]
fn review_decision_updates_search_projection() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_review_decision_event(&log);

    db.apply_event(&event).unwrap();

    assert!(projected_triage_text(&db, "fp3_search").contains("verified sink evidence"));
    assert_verified_search_hit_when_fts_available(&db);
}

#[test]
fn review_decision_requires_confidence_millis() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = log
        .append(
            EventKind::TriageDecided,
            "human",
            Some("run-1".to_string()),
            None,
            serde_json::json!({
                "stableFp": "fp3_search",
                "findingId": 7,
                "identityId": "fi_search",
                "verdict": "confirmed",
                "rationale": "verified sink evidence",
                "author": "human",
            }),
        )
        .unwrap();

    let error = db.apply_event(&event).unwrap_err();

    assert!(error.to_string().contains("confidenceMillis"));
}

#[test]
fn rekey_projection_requires_confidence() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = log
        .append(
            EventKind::FindingRekeyed,
            "rekeyer",
            None,
            None,
            serde_json::json!({
                "oldFp": "fp3_old",
                "newFp": "fp3_new",
                "method": "exact_content",
            }),
        )
        .unwrap();

    let error = db.apply_event(&event).unwrap_err();

    assert!(error.to_string().contains("confidence"));
}

#[test]
fn snapshot_and_file_events_project_inventory_rows() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let snapshot = append_snapshot_event(&log);
    let file = append_file_event(&log);

    db.apply_event(&snapshot).unwrap();
    db.apply_event(&file).unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, file.seq);
    assert_eq!(projected_snapshot_tree(&db, "snap3_test"), "tree3_test");
    assert_eq!(
        projected_indexed_file_blob(&db, "snap3_test", "src/db.rs"),
        "blob3_test"
    );
    assert_eq!(projected_blob_size(&db, "blob3_test"), 128);
}

#[test]
fn finding_observation_projects_current_finding_and_search_row() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_observation_event(&log, "obs3_a", "high", "SQL injection");

    db.apply_event(&event).unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, event.seq);
    assert_eq!(projected_observation_count(&db, "fp3_observed"), 1);
    assert_eq!(
        projected_current_finding(&db, "fp3_observed"),
        (
            "open".to_string(),
            "high".to_string(),
            "SQL injection".to_string()
        )
    );
    assert!(projected_search_message(&db, "fp3_observed").contains("raw query"));
}

#[test]
fn repeated_observation_updates_current_finding_without_changing_first_seen() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let first = append_observation_event(&log, "obs3_a", "medium", "Initial title");
    let second = append_observation_event(&log, "obs3_b", "critical", "Updated title");

    db.apply_event(&first).unwrap();
    db.apply_event(&second).unwrap();

    assert_eq!(stable_finding_seen_range(&db, "fp3_observed"), (1, 2));
    assert_eq!(
        projected_current_finding(&db, "fp3_observed"),
        (
            "open".to_string(),
            "critical".to_string(),
            "Updated title".to_string()
        )
    );
}

#[test]
fn stable_finding_reads_carry_projection_watermark() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_observation_event(&log, "obs3_read", "high", "Readable title");
    db.apply_event(&event).unwrap();

    let read = db
        .list_stable_findings(ReadOptions::require_min_seq(event.seq))
        .unwrap();

    assert_eq!(read.applied_seq, event.seq);
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].stable_fp, "fp3_observed");
    assert_eq!(read.rows[0].canonical_title, "Readable title");
}

#[test]
fn stable_finding_reads_reject_stale_projection_when_required() {
    let db = ProjectionDb::open_in_memory().unwrap();

    let error = db
        .list_stable_findings(ReadOptions::require_min_seq(1))
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("projection watermark 0 is behind required read seq 1"));
}

#[test]
fn stable_finding_reads_wait_for_projection_watermark() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let log_dir = tmp.path().join("log");
    let reader = ProjectionDb::open(&db_path).unwrap();
    let writer_path = db_path.clone();
    let writer_log_dir = log_dir.clone();
    let writer = std::thread::spawn(move || {
        let log = EventLog::open(writer_log_dir).unwrap();
        let first = append_snapshot_event(&log);
        let second = append_file_event(&log);
        let writer = ProjectionDb::open(writer_path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(25));
        writer.apply_event(&first).unwrap();
        writer.apply_event(&second).unwrap();
    });

    let read = reader
        .list_stable_findings(ReadOptions::wait_for_min_seq_with_poll(
            2,
            // Generous: a saturated full-suite run can starve the writer
            // thread well past a 1s budget. Timeout semantics are covered
            // separately by stable_finding_reads_wait_timeout_is_explicit.
            std::time::Duration::from_secs(10),
            std::time::Duration::from_millis(5),
        ))
        .unwrap();
    writer.join().unwrap();

    assert_eq!(read.applied_seq, 2);
    assert!(read.rows.is_empty());
}

#[test]
fn stable_finding_reads_wait_timeout_is_explicit() {
    let db = ProjectionDb::open_in_memory().unwrap();

    let error = db
        .list_stable_findings(ReadOptions::wait_for_min_seq_with_poll(
            1,
            std::time::Duration::from_millis(0),
            std::time::Duration::from_millis(0),
        ))
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("timed out waiting for projection watermark 0 to reach required read seq 1"));
}

fn append_finding_event(log: &EventLog) -> EventEnvelope {
    log.append(
        EventKind::TriageDecided,
        "reviewer",
        Some("run-1".to_string()),
        None,
        serde_json::json!({"stableFp": "fp3_test", "decision": "confirmed"}),
    )
    .unwrap()
}

fn append_review_decision_event(log: &EventLog) -> EventEnvelope {
    log.append(
        EventKind::TriageDecided,
        "human",
        Some("run-1".to_string()),
        None,
        serde_json::json!({
            "stableFp": "fp3_search",
            "findingId": 7,
            "identityId": "fi_search",
            "verdict": "confirmed",
            "rationale": "verified sink evidence",
            "author": "human",
            "confidenceMillis": 1000,
        }),
    )
    .unwrap()
}

fn append_snapshot_event(log: &EventLog) -> EventEnvelope {
    log.append(
        EventKind::SnapshotIndexed,
        "indexer",
        None,
        None,
        serde_json::json!({
            "snapshotHash": "snap3_test",
            "treeHash": "tree3_test",
            "workspaceRootFingerprint": "workspace",
            "gitCommit": "abc",
            "gitBranch": "main",
            "dirtyHash": null,
            "indexHash": null,
            "configHash": null,
        }),
    )
    .unwrap()
}

fn append_file_event(log: &EventLog) -> EventEnvelope {
    log.append(
        EventKind::FileIndexed,
        "indexer",
        None,
        None,
        serde_json::json!({
            "snapshotHash": "snap3_test",
            "path": "src/db.rs",
            "blobHash": "blob3_test",
            "storagePath": "objects/blake3/bl/ob/blob3_test",
            "fileSize": 128,
            "mtimeNs": 9,
            "gitBlobOid": "git-blob",
            "language": "rust",
            "astHash": "ast3_test",
        }),
    )
    .unwrap()
}

fn append_observation_event(
    log: &EventLog,
    observation_hash: &str,
    severity: &str,
    title: &str,
) -> EventEnvelope {
    log.append(
        EventKind::FindingObserved,
        "scanner",
        Some("run-1".to_string()),
        None,
        serde_json::json!({
            "observationHash": observation_hash,
            "stableFp": "fp3_observed",
            "snapshotHash": "snap3_test",
            "runId": "run-1",
            "tool": "semgrep",
            "toolVersion": "1.2.3",
            "ruleId": "CWE-89",
            "ruleSetHash": "rules3",
            "severity": severity,
            "title": title,
            "message": "raw query reaches sink",
            "blobHash": "blob3_test",
            "byteStart": 10,
            "byteEnd": 20,
            "displayPath": "src/db.rs",
            "displayLine": 7,
            "rawResultHash": "raw3_test",
        }),
    )
    .unwrap()
}

fn projected_snapshot_tree(db: &ProjectionDb, snapshot_hash: &str) -> String {
    db.conn
        .query_row(
            "select tree_hash from target_snapshots where snapshot_hash = ?1",
            params![snapshot_hash],
            |row| row.get(0),
        )
        .unwrap()
}

fn projected_blob_size(db: &ProjectionDb, blob_hash: &str) -> i64 {
    db.conn
        .query_row(
            "select size_bytes from blobs where blob_hash = ?1",
            params![blob_hash],
            |row| row.get(0),
        )
        .unwrap()
}

fn projected_indexed_file_blob(db: &ProjectionDb, snapshot_hash: &str, path: &str) -> String {
    db.conn
        .query_row(
            "select blob_hash from indexed_files where snapshot_hash = ?1 and path = ?2",
            params![snapshot_hash, path],
            |row| row.get(0),
        )
        .unwrap()
}

fn projected_event_stable_fp(db: &ProjectionDb, seq: u64) -> String {
    db.conn
        .query_row(
            "select stable_fp from finding_events where seq = ?1",
            params![seq as i64],
            |row| row.get(0),
        )
        .unwrap()
}

fn projected_observation_count(db: &ProjectionDb, stable_fp: &str) -> i64 {
    db.conn
        .query_row(
            "select count(*) from finding_observations where stable_fp = ?1",
            params![stable_fp],
            |row| row.get(0),
        )
        .unwrap()
}

fn projected_current_finding(db: &ProjectionDb, stable_fp: &str) -> (String, String, String) {
    db.conn
        .query_row(
            "select current_status, canonical_severity, canonical_title
               from stable_findings
              where stable_fp = ?1",
            params![stable_fp],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn stable_finding_seen_range(db: &ProjectionDb, stable_fp: &str) -> (i64, i64) {
    db.conn
        .query_row(
            "select first_seen_seq, last_seen_seq from stable_findings where stable_fp = ?1",
            params![stable_fp],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn projected_search_message(db: &ProjectionDb, stable_fp: &str) -> String {
    db.conn
        .query_row(
            "select message from finding_search_content where stable_fp = ?1",
            params![stable_fp],
            |row| row.get(0),
        )
        .unwrap()
}

fn projected_triage_text(db: &ProjectionDb, stable_fp: &str) -> String {
    db.conn
        .query_row(
            "select triage_text from finding_search_content where stable_fp = ?1",
            params![stable_fp],
            |row| row.get(0),
        )
        .unwrap()
}

fn assert_verified_search_hit_when_fts_available(db: &ProjectionDb) {
    if meta_u64(&db.conn, "fts_available").unwrap_or(0) == 0 {
        return;
    }
    assert_eq!(search_hit_count(db, "verified"), 1);
}

fn search_hit_count(db: &ProjectionDb, query: &str) -> i64 {
    db.conn
        .query_row(
            "select count(*) from finding_search where finding_search match ?1",
            params![query],
            |row| row.get(0),
        )
        .unwrap()
}
