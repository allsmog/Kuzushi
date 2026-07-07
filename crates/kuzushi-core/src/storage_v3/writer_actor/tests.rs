use super::*;
use crate::event_log::EventEnvelope;

fn decision(stable_fp: &str, read_watermark: u64) -> DecisionWrite {
    DecisionWrite {
        stable_fp: stable_fp.to_string(),
        finding_id: Some(7),
        identity_id: Some("fi_test".to_string()),
        verdict: "confirmed".to_string(),
        author: "human".to_string(),
        rationale: "reviewed".to_string(),
        confidence_millis: 1000,
        read_watermark,
    }
}

fn observation(observation_hash: &str) -> ObservationWrite {
    ObservationWrite {
        observation_hash: observation_hash.to_string(),
        stable_fp: "fp3_observed".to_string(),
        snapshot_hash: "snap3_test".to_string(),
        run_id: "run-1".to_string(),
        tool: "semgrep".to_string(),
        tool_version: Some("1.2.3".to_string()),
        rule_id: "CWE-89".to_string(),
        rule_set_hash: Some("rules3".to_string()),
        severity: "high".to_string(),
        title: "SQL injection".to_string(),
        message: "raw query reaches sink".to_string(),
        blob_hash: Some("blob3_test".to_string()),
        byte_start: Some(10),
        byte_end: Some(20),
        display_path: Some("src/db.rs".to_string()),
        display_line: Some(7),
        raw_result_hash: "raw3_test".to_string(),
        finding_json: None,
        actor: "scanner".to_string(),
    }
}

fn rekey(old_fp: &str, new_fp: &str, confidence_millis: u16) -> RekeyWrite {
    RekeyWrite {
        old_fp: old_fp.to_string(),
        new_fp: new_fp.to_string(),
        method: "exact_content".to_string(),
        confidence_millis,
        actor: "rekeyer".to_string(),
        evidence: None,
    }
}

fn verification(stable_fp: &str) -> VerificationWrite {
    VerificationWrite {
        stable_fp: stable_fp.to_string(),
        finding_id: Some(7),
        identity_id: Some("fi_test".to_string()),
        proof_level: 4,
        proof_verdict: "exploited".to_string(),
        backend: "bwrap".to_string(),
        language: Some("rust".to_string()),
        harness_path: Some("/tmp/harness".to_string()),
        crash_evidence: Some("panic: sink reached".to_string()),
        duration_ms: 123,
        cost_usd_micros: 50_000,
        notes: vec!["empirical proof".to_string()],
        actor: "verification".to_string(),
    }
}

fn patch_attempt(stable_fp: &str) -> PatchAttemptWrite {
    PatchAttemptWrite {
        stable_fp: stable_fp.to_string(),
        fingerprint: "legacy-fp".to_string(),
        patch_run_id: "patch-run-1".to_string(),
        repo: "/repo".to_string(),
        diff_object: Some("diff-object-hash".to_string()),
        diff_size_bytes: Some(99),
        status: "VERIFIED".to_string(),
        iterations: 2,
        build_command: Some("cargo build".to_string()),
        test_command: Some("cargo test".to_string()),
        worktree_path: Some("/tmp/worktree".to_string()),
        cost_usd_micros: Some(125_000),
        validator_log: Some("tests passed".to_string()),
        history_json: "[]".to_string(),
        actor: "patch-runner".to_string(),
    }
}

fn audit_event(event_kind: EventKind) -> AuditWrite {
    AuditWrite {
        event_kind,
        actor: "diagnostics".to_string(),
        run_id: Some("run-audit".to_string()),
        stable_fp: Some("fp3_audit".to_string()),
        subject: Some("plugin:demo".to_string()),
        summary: "captured audit detail".to_string(),
        details: serde_json::json!({"code": "demo.audit"}),
    }
}

fn run_lifecycle(event_kind: EventKind, status: &str) -> RunLifecycleWrite {
    RunLifecycleWrite {
        event_kind,
        run_id: "run-lifecycle".to_string(),
        target: Some("/repo".to_string()),
        status: status.to_string(),
        findings_count: (event_kind != EventKind::RunStarted).then_some(3),
        actor: "runner".to_string(),
    }
}

fn finding_lifecycle(event_kind: EventKind) -> FindingLifecycleWrite {
    FindingLifecycleWrite {
        event_kind,
        stable_fp: "fp3_observed".to_string(),
        reason: Some("state transition test".to_string()),
        actor: "state-machine".to_string(),
        run_id: None,
    }
}

fn snapshot() -> SnapshotWrite {
    SnapshotWrite {
        snapshot_hash: "snap3_test".to_string(),
        tree_hash: "tree3_test".to_string(),
        workspace_root_fingerprint: "workspace".to_string(),
        git_commit: Some("abc".to_string()),
        git_branch: Some("main".to_string()),
        dirty_hash: None,
        index_hash: None,
        config_hash: None,
        actor: "indexer".to_string(),
    }
}

fn file_fact() -> FileFactWrite {
    FileFactWrite {
        snapshot_hash: "snap3_test".to_string(),
        path: "src/db.rs".to_string(),
        blob_hash: "blob3_test".to_string(),
        storage_path: Some("objects/blake3/bl/ob/blob3_test".to_string()),
        file_size: 128,
        mtime_ns: Some(9),
        git_blob_oid: Some("git-blob".to_string()),
        language: Some("rust".to_string()),
        ast_hash: Some("ast3_test".to_string()),
        actor: "indexer".to_string(),
    }
}

fn file_deleted() -> FileDeletedWrite {
    FileDeletedWrite {
        snapshot_hash: "snap3_test".to_string(),
        path: "src/db.rs".to_string(),
        actor: "indexer".to_string(),
    }
}

fn attack_surface() -> AttackSurfaceWrite {
    AttackSurfaceWrite {
        snapshot_hash: "snap3_test".to_string(),
        run_id: Some("run-attack-surface".to_string()),
        object_hash: Some("attack-surface-object".to_string()),
        summary: "2 routes, 1 trust boundary".to_string(),
        actor: "indexer".to_string(),
    }
}

fn count_where(conn: &rusqlite::Connection, table: &str, predicate: &str) -> i64 {
    conn.query_row(
        &format!("select count(*) from {table} where {predicate}"),
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn stable_status(db_path: &std::path::Path, stable_fp: &str) -> String {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select current_status from stable_findings where stable_fp = ?1",
        [stable_fp],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn storage_writer_records_decision_event_and_projection_watermark() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();

    let receipt = writer.record_review_decision(decision("fp3_a", 0)).unwrap();

    assert_eq!(receipt.committed_seq, 1);
    assert_eq!(writer.current_watermark().unwrap(), 1);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_kind, EventKind::TriageDecided);
}

#[test]
fn storage_writer_records_observation_event_and_projection_watermark() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();

    let receipt = writer
        .record_finding_observation(observation("obs3_a"))
        .unwrap();

    assert_eq!(receipt.committed_seq, 1);
    assert_eq!(writer.current_watermark().unwrap(), 1);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_kind, EventKind::FindingObserved);
}

#[test]
fn storage_writer_records_snapshot_and_file_index_events() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();

    writer.record_snapshot_indexed(snapshot()).unwrap();
    let receipt = writer.record_file_indexed(file_fact()).unwrap();

    assert_eq!(receipt.committed_seq, 2);
    assert_eq!(writer.current_watermark().unwrap(), 2);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[0].event_kind, EventKind::SnapshotIndexed);
    assert_eq!(events[1].event_kind, EventKind::FileIndexed);
}

#[test]
fn storage_writer_records_file_deleted_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();
    writer.record_snapshot_indexed(snapshot()).unwrap();
    writer.record_file_indexed(file_fact()).unwrap();

    let receipt = writer.record_file_deleted(file_deleted()).unwrap();

    assert_eq!(receipt.committed_seq, 3);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    assert_eq!(count_where(&conn, "indexed_files", "1 = 1"), 0);
    assert_eq!(count_where(&conn, "file_deletions", "path = 'src/db.rs'"), 1);
}

#[test]
fn storage_writer_records_attack_surface_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();

    let receipt = writer.record_attack_surface_indexed(attack_surface()).unwrap();

    assert_eq!(receipt.committed_seq, 1);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let projected: (String, String, String) = conn
        .query_row(
            "select snapshot_hash, object_hash, summary from attack_surface_snapshots",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        projected,
        (
            "snap3_test".to_string(),
            "attack-surface-object".to_string(),
            "2 routes, 1 trust boundary".to_string()
        )
    );
}

#[test]
fn storage_writer_checkpoint_appends_event_and_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();
    writer.record_finding_observation(observation("obs3_before_checkpoint")).unwrap();

    let receipt = writer.record_checkpoint().unwrap();

    assert_eq!(receipt.committed_seq, 2);
    assert_eq!(writer.current_watermark().unwrap(), 2);
    let checkpoint_path = tmp
        .path()
        .join("log/checkpoints/checkpoint-000000000002.json");
    assert!(checkpoint_path.exists(), "expected {}", checkpoint_path.display());
    let checkpoint: EventEnvelope =
        serde_json::from_str(&std::fs::read_to_string(checkpoint_path).unwrap()).unwrap();
    assert_eq!(checkpoint.event_kind, EventKind::ProjectionCheckpointed);
    assert_eq!(
        checkpoint.payload["appliedSeqBeforeCheckpoint"].as_u64(),
        Some(1)
    );
}

#[test]
fn storage_writer_compact_appends_event_checkpoint_and_returns_live() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();
    writer
        .record_finding_observation(observation("obs3_before_compact"))
        .unwrap();

    let receipt = writer.compact_log().unwrap();

    assert_eq!(receipt.committed_seq, 2);
    assert_eq!(writer.lifecycle.state(), WriterActorState::Live);
    assert_eq!(writer.current_watermark().unwrap(), 2);
    let checkpoint_path = tmp
        .path()
        .join("log/checkpoints/checkpoint-000000000002.json");
    assert!(checkpoint_path.exists(), "expected {}", checkpoint_path.display());
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[1].event_kind, EventKind::CompactionCompleted);
    assert_eq!(events[1].payload["segmentRollover"].as_bool(), Some(true));
    assert_eq!(events[1].payload["compactedThroughSeq"].as_u64(), Some(1));
    assert!(tmp.path().join("log/events-000001.jsonl").exists());
}

#[test]
fn storage_writer_appends_to_rolled_segment_after_compaction() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();
    writer
        .record_finding_observation(observation("obs3_before_rollover"))
        .unwrap();
    writer.compact_log().unwrap();

    let receipt = writer
        .record_finding_observation(observation("obs3_after_rollover"))
        .unwrap();

    assert_eq!(receipt.committed_seq, 3);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    log.verify_chain().unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].event_kind, EventKind::FindingObserved);
    let rolled_segment = std::fs::read_to_string(tmp.path().join("log/events-000001.jsonl"))
        .expect("rolled segment should contain the next append");
    assert!(rolled_segment.contains("obs3_after_rollover"));
}

#[test]
fn storage_writer_rejects_stale_decision_for_changed_finding() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();
    writer.record_review_decision(decision("fp3_a", 0)).unwrap();

    let error = writer
        .record_review_decision(decision("fp3_a", 0))
        .unwrap_err();

    assert!(error.to_string().contains("changed after read watermark 0"));
}

#[test]
fn storage_writer_records_rekey_edge_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();

    let receipt = writer
        .record_rekey(rekey("fp3_old", "fp3_new", 950))
        .unwrap();

    assert_eq!(receipt.committed_seq, 1);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let edge: (String, String, String) = conn
        .query_row(
            "select old_fp, new_fp, method from rekey_edges",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        edge,
        (
            "fp3_old".to_string(),
            "fp3_new".to_string(),
            "exact_content".to_string()
        )
    );
}

#[test]
fn storage_writer_records_verification_event_and_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();

    let receipt = writer.record_verification(verification("fp3_verified")).unwrap();

    assert_eq!(receipt.committed_seq, 1);
    assert_eq!(writer.current_watermark().unwrap(), 1);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[0].event_kind, EventKind::VerificationRecorded);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let projected: (String, i64, String, f64) = conn
        .query_row(
            "select stable_fp, proof_level, proof_verdict, cost_usd from verification_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(projected.0, "fp3_verified");
    assert_eq!(projected.1, 4);
    assert_eq!(projected.2, "exploited");
    assert!((projected.3 - 0.05).abs() < 1e-9);
}

#[test]
fn storage_writer_records_patch_attempt_event_and_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();

    let receipt = writer
        .record_patch_attempt(patch_attempt("fp3_patch"))
        .unwrap();

    assert_eq!(receipt.committed_seq, 1);
    assert_eq!(writer.current_watermark().unwrap(), 1);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[0].event_kind, EventKind::PatchAttemptRecorded);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let projected: (String, String, String, f64) = conn
        .query_row(
            "select stable_fp, patch_run_id, status, cost_usd from patch_attempt_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(projected.0, "fp3_patch");
    assert_eq!(projected.1, "patch-run-1");
    assert_eq!(projected.2, "VERIFIED");
    assert!((projected.3 - 0.125).abs() < 1e-9);
}

#[test]
fn storage_writer_records_audit_event_and_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();

    let receipt = writer
        .execute_command(WriterCommand::Decision(DecisionCommand::RecordAudit(
            audit_event(EventKind::DiagnosticRecorded),
        )))
        .unwrap();

    assert_eq!(receipt.committed_seq, 1);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[0].event_kind, EventKind::DiagnosticRecorded);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let projected: (String, String, String, String) = conn
        .query_row(
            "select event_kind, run_id, stable_fp, summary from audit_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        projected,
        (
            "diagnostic-recorded".to_string(),
            "run-audit".to_string(),
            "fp3_audit".to_string(),
            "captured audit detail".to_string()
        )
    );
}

#[test]
fn storage_writer_records_run_lifecycle_and_state_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();

    writer
        .execute_command(WriterCommand::Decision(DecisionCommand::RecordRunLifecycle(
            run_lifecycle(EventKind::RunStarted, "running"),
        )))
        .unwrap();
    let receipt = writer
        .execute_command(WriterCommand::Decision(DecisionCommand::RecordRunLifecycle(
            run_lifecycle(EventKind::RunCompleted, "completed"),
        )))
        .unwrap();

    assert_eq!(receipt.committed_seq, 2);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let events_count: i64 = conn
        .query_row("select count(*) from run_events", [], |row| row.get(0))
        .unwrap();
    let state: (String, String, i64, i64, i64) = conn
        .query_row(
            "select run_id, status, findings_count, started_seq, completed_seq from run_states",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .unwrap();
    assert_eq!(events_count, 2);
    assert_eq!(
        state,
        (
            "run-lifecycle".to_string(),
            "completed".to_string(),
            3,
            1,
            2
        )
    );
}

#[test]
fn finding_lifecycle_events_update_stable_finding_status() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();
    writer
        .record_finding_observation(observation("obs3_lifecycle"))
        .unwrap();
    let mut suppress = decision("fp3_observed", 1);
    suppress.verdict = "suppressed".to_string();
    writer.record_review_decision(suppress).unwrap();
    assert_eq!(stable_status(&db_path, "fp3_observed"), "suppressed");

    writer
        .execute_command(WriterCommand::Decision(
            DecisionCommand::RecordFindingLifecycle(finding_lifecycle(EventKind::SuppressionRemoved)),
        ))
        .unwrap();
    assert_eq!(stable_status(&db_path, "fp3_observed"), "open");

    writer
        .execute_command(WriterCommand::Decision(
            DecisionCommand::RecordFindingLifecycle(finding_lifecycle(EventKind::FindingDisappeared)),
        ))
        .unwrap();
    assert_eq!(stable_status(&db_path, "fp3_observed"), "stale");
}

#[test]
fn storage_writer_rejects_non_audit_kind_for_audit_write() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();

    let error = writer
        .execute_command(WriterCommand::Decision(DecisionCommand::RecordAudit(
            audit_event(EventKind::TriageDecided),
        )))
        .unwrap_err();

    assert!(error.to_string().contains("is not a writer audit event"));
}

#[test]
fn rebuild_projection_clears_disposable_rows_and_replays_log() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let mut writer = StorageWriter::open(tmp.path().join("log"), &db_path).unwrap();
    writer
        .record_finding_observation(observation("obs3_rebuild"))
        .unwrap();
    writer
        .record_verification(verification("fp3_observed"))
        .unwrap();
    writer
        .projection
        .conn
        .execute(
            r#"
            insert into stable_findings(
              stable_fp, current_status, canonical_severity, canonical_title,
              first_seen_seq, last_seen_seq, updated_seq
            )
            values ('stale_projection_row', 'open', 'low', 'stale', 99, 99, 99)
            "#,
            [],
        )
        .unwrap();

    let receipt = writer
        .execute_command(WriterCommand::Control(ControlCommand::RebuildProjection))
        .unwrap();

    assert_eq!(receipt.committed_seq, 2);
    assert_eq!(receipt.projection_generation, 1);
    assert_eq!(writer.lifecycle.state(), WriterActorState::Live);
    assert_eq!(writer.current_watermark().unwrap(), 2);
    let conn = rusqlite::Connection::open(db_path).unwrap();
    assert_eq!(
        count_where(&conn, "stable_findings", "stable_fp = 'stale_projection_row'"),
        0
    );
    assert_eq!(count_where(&conn, "finding_observations", "1 = 1"), 1);
    assert_eq!(count_where(&conn, "verification_events", "1 = 1"), 1);
}

#[test]
fn stale_decision_forwards_through_safe_rekey() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();
    writer
        .record_rekey(rekey("fp3_old", "fp3_new", 950))
        .unwrap();

    let receipt = writer
        .record_review_decision(decision("fp3_old", 0))
        .unwrap();

    assert_eq!(receipt.committed_seq, 2);
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[1].event_kind, EventKind::TriageDecided);
    assert_eq!(events[1].payload["stableFp"], "fp3_new");
}

#[test]
fn stale_decision_rejects_low_confidence_rekey() {
    let tmp = tempfile::tempdir().unwrap();
    let mut writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();
    writer
        .record_rekey(rekey("fp3_old", "fp3_new", 500))
        .unwrap();

    let error = writer
        .record_review_decision(decision("fp3_old", 0))
        .unwrap_err();

    assert!(error.to_string().contains("low confidence"));
}

#[test]
fn storage_writer_replays_log_when_projection_lags() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    log.append(
        EventKind::TriageDecided,
        "human",
        None,
        None,
        decision("fp3_replay", 0).payload(),
    )
    .unwrap();

    let writer =
        StorageWriter::open(tmp.path().join("log"), tmp.path().join("index.sqlite3")).unwrap();

    assert_eq!(writer.current_watermark().unwrap(), 1);
}

#[test]
fn recovery_rejects_projection_ahead_of_log() {
    let mut lifecycle = WriterLifecycle::recovering();

    let error = lifecycle.recover(2, 3).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("projection watermark 3 is ahead of event log head 2")
    );
}

#[test]
fn recovery_replays_until_projection_catches_log_head() {
    let mut lifecycle = WriterLifecycle::recovering();

    lifecycle.recover(3, 1).unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Replaying);

    lifecycle.projection_advanced(2).unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Replaying);

    lifecycle.projection_advanced(3).unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Live);
}

#[test]
fn live_appends_allow_projection_to_lag_but_not_lead() {
    let mut lifecycle = WriterLifecycle::recovering();
    lifecycle.recover(1, 1).unwrap();

    lifecycle.append_committed_event(2).unwrap();
    assert_eq!(lifecycle.applied_seq(), 1);
    assert_eq!(lifecycle.log_head(), 2);
    assert!(lifecycle.projection_advanced(3).is_err());
}

#[test]
fn only_watcher_commands_are_coalescible() {
    let control = WriterCommand::Control(ControlCommand::Checkpoint);
    let decision = WriterCommand::Decision(DecisionCommand::ReviewDecision(decision("fp3_a", 0)));
    let watcher = WriterCommand::Watcher(WatcherCommand::FileFactsChanged {
        path: "src/main.rs".to_string(),
    });

    assert_eq!(control.lane(), WriteLane::Control);
    assert_eq!(decision.lane(), WriteLane::Decision);
    assert_eq!(watcher.lane(), WriteLane::Watcher);
    assert!(!control.can_be_coalesced());
    assert!(!decision.can_be_coalesced());
    assert!(watcher.can_be_coalesced());
}

#[test]
fn scheduler_drains_control_then_bounded_decisions_then_one_watcher() {
    let mut scheduler = WriterLaneScheduler::new(2);
    scheduler.push(WriterCommand::Watcher(WatcherCommand::FileFactsChanged {
        path: "src/a.rs".to_string(),
    }));
    scheduler.push(WriterCommand::Decision(DecisionCommand::ReviewDecision(
        decision("fp3_a", 0),
    )));
    scheduler.push(WriterCommand::Decision(DecisionCommand::ReviewDecision(
        decision("fp3_b", 0),
    )));
    scheduler.push(WriterCommand::Decision(DecisionCommand::ReviewDecision(
        decision("fp3_c", 0),
    )));
    scheduler.push(WriterCommand::Control(ControlCommand::Checkpoint));

    let batch = scheduler.next_batch();

    assert_eq!(
        batch.iter().map(WriterCommand::lane).collect::<Vec<_>>(),
        vec![
            WriteLane::Control,
            WriteLane::Decision,
            WriteLane::Decision,
            WriteLane::Watcher,
        ]
    );
    assert_eq!(
        scheduler
            .next_batch()
            .iter()
            .map(WriterCommand::lane)
            .collect::<Vec<_>>(),
        vec![WriteLane::Decision]
    );
}

#[test]
fn scheduler_coalesces_watcher_updates_but_not_decisions() {
    let mut scheduler = WriterLaneScheduler::new(8);
    scheduler.push(WriterCommand::Watcher(WatcherCommand::FileFactsChanged {
        path: "src/a.rs".to_string(),
    }));
    scheduler.push(WriterCommand::Watcher(WatcherCommand::FileFactsChanged {
        path: "src/a.rs".to_string(),
    }));
    scheduler.push(WriterCommand::Decision(DecisionCommand::ReviewDecision(
        decision("fp3_a", 0),
    )));
    scheduler.push(WriterCommand::Decision(DecisionCommand::ReviewDecision(
        decision("fp3_a", 0),
    )));

    let batch = scheduler.next_batch();

    assert_eq!(
        batch.iter().map(WriterCommand::lane).collect::<Vec<_>>(),
        vec![WriteLane::Decision, WriteLane::Decision, WriteLane::Watcher]
    );
}

#[test]
fn rebuild_and_compaction_return_to_live_or_replay() {
    let mut lifecycle = WriterLifecycle::recovering();
    lifecycle.recover(5, 5).unwrap();

    lifecycle.begin_rebuild().unwrap();
    lifecycle.finish_rebuild(4).unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Replaying);
    lifecycle.projection_advanced(5).unwrap();

    lifecycle.begin_compaction().unwrap();
    lifecycle.finish_compaction(6, 5).unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Replaying);
}

#[test]
fn shutdown_drains_before_stopping() {
    let mut lifecycle = WriterLifecycle::recovering();
    lifecycle.recover(0, 0).unwrap();

    lifecycle.begin_shutdown().unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Draining);
    lifecycle.finish_shutdown().unwrap();
    assert_eq!(lifecycle.state(), WriterActorState::Stopped);
}

#[tokio::test]
async fn storage_writer_actor_commits_watcher_and_decision_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let actor = StorageWriterActor::spawn(
        tmp.path().join("log"),
        tmp.path().join("index.sqlite3"),
        StorageWriterActorConfig::default(),
    );

    let first = actor
        .watcher(WatcherCommand::FindingObservation(observation("obs3_actor")))
        .await
        .unwrap();
    let second = actor
        .decision(DecisionCommand::ReviewDecision(decision("fp3_actor", first.committed_seq)))
        .await
        .unwrap();

    assert_eq!(first.committed_seq, 1);
    assert_eq!(second.committed_seq, 2);
    actor.shutdown().await.unwrap();
    let log = EventLog::open(tmp.path().join("log")).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events[0].event_kind, EventKind::FindingObserved);
    assert_eq!(events[1].event_kind, EventKind::TriageDecided);
}

#[tokio::test]
async fn storage_writer_actor_barrier_reports_projection_watermark() {
    let tmp = tempfile::tempdir().unwrap();
    let actor = StorageWriterActor::spawn(
        tmp.path().join("log"),
        tmp.path().join("index.sqlite3"),
        StorageWriterActorConfig::default(),
    );

    let receipt = actor.control(ControlCommand::Barrier).await.unwrap();

    assert_eq!(receipt.committed_seq, 0);
    assert_eq!(receipt.event_hash, "barrier");
    actor.shutdown().await.unwrap();
}

#[test]
fn executable_watcher_events_are_not_coalesced() {
    assert!(!WriterCommand::Watcher(WatcherCommand::FindingObservation(
        observation("obs3_not_coalesced")
    ))
    .can_be_coalesced());
    assert!(!WriterCommand::Watcher(WatcherCommand::FileIndexed(file_fact())).can_be_coalesced());
    assert!(WriterCommand::Watcher(WatcherCommand::FileFactsChanged {
        path: "src/main.rs".to_string(),
    })
    .can_be_coalesced());
}
