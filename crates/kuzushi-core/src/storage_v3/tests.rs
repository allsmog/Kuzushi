use super::*;
use crate::event_log::{EventEnvelope, EventKind, EventLog};

#[test]
fn projection_starts_at_zero_watermark() {
    let db = ProjectionDb::open_in_memory().unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, 0);
    assert_eq!(db.meta().unwrap().generation, 0);
}

#[test]
fn projection_watermark_updates_through_meta() {
    let db = ProjectionDb::open_in_memory().unwrap();

    db.set_applied_seq(42).unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, 42);
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
        ("open".to_string(), "high".to_string(), "SQL injection".to_string())
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
        ("open".to_string(), "critical".to_string(), "Updated title".to_string())
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

    assert!(
        error
            .to_string()
            .contains("projection watermark 0 is behind required read seq 1")
    );
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
            params![seq],
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
