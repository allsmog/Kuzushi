use super::*;
use crate::event_log::{EventEnvelope, EventKind, EventLog};

#[test]
fn projection_starts_at_zero_watermark() {
    let db = ProjectionDb::open_in_memory().unwrap();

    assert_eq!(db.meta().unwrap().applied_seq, 0);
    assert_eq!(db.meta().unwrap().generation, 0);
}

#[test]
fn opening_legacy_projection_adds_nullable_threat_model_ref_columns() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table threat_model_versions (
          id integer primary key autoincrement, created_at text not null,
          source text not null, run_id text, methodology text not null,
          threat_count integer not null, sha256 text not null,
          document_json text not null
        );
        insert into threat_model_versions values
          (1, '1000', 'build', 'run-old', 'stride', 1, 'sha256:old', '{}');
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    assert!(table_has_column(&conn, "threat_model_versions", "model_id").unwrap());
    assert!(table_has_column(&conn, "threat_model_versions", "revision_id").unwrap());
    let refs: (Option<String>, Option<String>) = conn
        .query_row(
            "select model_id, revision_id from threat_model_versions where id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(refs, (None, None));
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
    assert!(table_has_column(&conn, "verification_events", "provenance_json").unwrap());
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
        assert!(table_has_column(&conn, table, "reverify_evidence_json").unwrap());
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
fn review_decision_projection_retains_event_provenance() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let with_watermark = log
        .append(
            EventKind::TriageDecided,
            "human",
            Some("run-1".to_string()),
            None,
            serde_json::json!({
                "stableFp": "fp3_prov",
                "findingId": 7,
                "verdict": "confirmed",
                "rationale": "verified",
                "author": "human",
                "confidenceMillis": 900,
                "readWatermark": 0,
            }),
        )
        .unwrap();
    let legacy_without_watermark = append_review_decision_event(&log);

    db.apply_event(&with_watermark).unwrap();
    db.apply_event(&legacy_without_watermark).unwrap();

    let rows: Vec<(i64, String, Option<i64>)> = db
        .conn
        .prepare(
            "select decision_event_seq, decision_event_hash, decision_read_watermark
               from review_decisions order by id asc",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        rows[0],
        (
            with_watermark.seq as i64,
            with_watermark.event_hash.as_str().to_string(),
            Some(0)
        )
    );
    assert_eq!(
        rows[1],
        (
            legacy_without_watermark.seq as i64,
            legacy_without_watermark.event_hash.as_str().to_string(),
            None
        )
    );
}

#[test]
fn opening_legacy_projection_backfills_decision_provenance_from_finding_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table review_decisions (
          id integer primary key autoincrement,
          finding_id integer not null,
          identity_id text,
          decision_verdict text not null,
          triage_verdict text,
          confidence real not null,
          rationale text not null,
          author text not null,
          created_at text not null,
          dismiss_reason text,
          dismissed_by text
        );
        create table finding_events (
          event_hash text primary key,
          seq integer not null unique,
          stable_fp text,
          event_kind text not null,
          payload_json text not null,
          actor text not null,
          created_at text not null
        );
        insert into finding_events values
          ('hash-5', 5, 'fp_a', 'triage-decided',
           '{"findingId":7,"verdict":"confirmed","readWatermark":4}',
           'human', '2026-01-01T00:00:00Z'),
          ('hash-6', 6, 'fp_a', 'finding-reopened',
           '{"stableFp":"fp_a"}', 'scanner', '2026-01-01T00:00:01Z'),
          ('hash-9', 9, 'fp_a', 'suppression-added',
           '{"findingId":7,"verdict":"suppressed"}',
           'human', '2026-01-02T00:00:00Z'),
          ('hash-12', 12, 'fp_a', 'triage-decided',
           '{"findingId":7,"verdict":"deferred","readWatermark":11}',
           'human', '2026-01-03T00:00:00Z');
        insert into review_decisions
          (finding_id, identity_id, decision_verdict, triage_verdict, confidence,
           rationale, author, created_at, dismiss_reason, dismissed_by)
        values
          (7, null, 'confirmed', 'true_positive', 0.9, 'r', 'human',
           '2026-01-01T00:00:00Z', null, null),
          (7, null, 'suppressed', null, 1.0, 'r', 'human',
           '2026-01-02T00:00:00Z', null, null),
          (7, null, 'deferred', null, 1.0, 'r', 'human',
           '2026-01-03T00:00:99Z', null, null);
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    let rows: Vec<(Option<i64>, Option<String>, Option<i64>)> = conn
        .prepare(
            "select decision_event_seq, decision_event_hash, decision_read_watermark
               from review_decisions order by id asc",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(rows[0], (Some(5), Some("hash-5".to_string()), Some(4)));
    assert_eq!(rows[1], (Some(9), Some("hash-9".to_string()), None));
    // Timestamp disagreement with the ranked event: provenance must stay
    // null rather than be misattributed.
    assert_eq!(rows[2], (None, None, None));

    // Re-opening after the one-shot backfill must not rewrite anything.
    drop(ProjectionDb::open(&db_path).unwrap());
    let unchanged: Option<i64> = conn
        .query_row(
            "select decision_event_seq from review_decisions where id = 3",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unchanged, None);
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
fn review_session_projects_to_review_sessions_table() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_review_session_event(&log, "session-1", "fp3_session");

    db.apply_event(&event).unwrap();

    let row: (String, i64, String, String, Option<String>, Option<i64>) = db
        .conn
        .query_row(
            "select event_hash, seq, review_session_id, stable_fp, identity_id, finding_id
               from review_sessions",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            event.event_hash.as_str().to_string(),
            event.seq as i64,
            "session-1".to_string(),
            "fp3_session".to_string(),
            Some("fi_session".to_string()),
            Some(7),
        )
    );

    let measurement: (
        String,
        Option<String>,
        i64,
        String,
        String,
        i64,
        Option<i64>,
        i64,
        String,
        String,
    ) = db
        .conn
        .query_row(
            "select feature_schema_id, feature_snapshot_hash, feature_cutoff_seq, model_id,
                    eligibility, baseline_rank, shadow_rank, queue_size, proof_band, severity
               from review_sessions",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        measurement,
        (
            "kuzushi-review-yield-features-v1".to_string(),
            Some("blake3:feature".to_string()),
            12_000,
            "blake3:model".to_string(),
            "eligible".to_string(),
            17,
            Some(5),
            133,
            "likely".to_string(),
            "high".to_string(),
        )
    );
}

/// A rank means a different thing under each objective, so the label the
/// session recorded must survive the projection unchanged.
#[test]
fn review_session_rank_objective_round_trips() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let mut payload = review_session_payload("session-1", "fp3_session");
    payload["shadowRankObjective"] = serde_json::json!("learn");
    let event = log
        .append(
            EventKind::ReviewSessionStarted,
            "operator",
            None,
            None,
            payload,
        )
        .unwrap();

    db.apply_event(&event).unwrap();

    let objective: Option<String> = db
        .conn
        .query_row(
            "select shadow_rank_objective from review_sessions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(objective, Some("learn".to_string()));
}

/// A session recorded before the objective was named reads as null rather than
/// being assumed into one ranking or the other.
#[test]
fn review_session_without_an_objective_projects_null() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_review_session_event(&log, "session-1", "fp3_session");

    db.apply_event(&event).unwrap();

    let objective: Option<String> = db
        .conn
        .query_row(
            "select shadow_rank_objective from review_sessions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(objective, None);
}

/// A projection DB created before the objective column existed gains it on
/// open, with its existing rows left unbackfilled.
#[test]
fn legacy_review_sessions_table_gains_the_rank_objective_column() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table review_sessions (
          event_hash text primary key,
          seq integer not null unique,
          review_session_id text not null unique,
          stable_fp text not null,
          identity_id text,
          finding_id integer,
          feature_schema_id text not null,
          feature_snapshot_hash text,
          feature_cutoff_seq integer not null,
          model_id text not null,
          eligibility text not null,
          baseline_rank integer not null,
          shadow_rank integer,
          queue_size integer not null,
          proof_band text not null,
          severity text not null,
          created_at text not null
        );
        insert into review_sessions
          (event_hash, seq, review_session_id, stable_fp, feature_schema_id,
           feature_cutoff_seq, model_id, eligibility, baseline_rank, shadow_rank,
           queue_size, proof_band, severity, created_at)
        values
          ('hash-1', 1, 'session-legacy', 'fp3_legacy', 'kuzushi-review-yield-features-v1',
           12000, 'blake3:model', 'eligible', 17, 5, 133, 'likely', 'high',
           '2026-01-01T00:00:00Z');
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    assert!(table_has_column(&conn, "review_sessions", "shadow_rank_objective").unwrap());
    let (rank, objective): (Option<i64>, Option<String>) = conn
        .query_row(
            "select shadow_rank, shadow_rank_objective from review_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(rank, Some(5));
    assert_eq!(objective, None);
}

/// A rebuilt projection must reproduce exactly one row per recorded session:
/// double-counted sessions would inflate every rate computed from them.
#[test]
fn review_session_projection_replay_is_idempotent() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_review_session_event(&log, "session-1", "fp3_session");

    db.apply_event(&event).unwrap();
    let tx = db.conn.unchecked_transaction().unwrap();
    apply_projection_event(&tx, &event).unwrap();
    tx.commit().unwrap();

    let (count, baseline): (i64, i64) = db
        .conn
        .query_row(
            "select count(*), max(baseline_rank) from review_sessions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(baseline, 17);

    // A full rebuild drops the row and reprojects exactly one.
    db.reset_for_rebuild().unwrap();
    let cleared: i64 = db
        .conn
        .query_row("select count(*) from review_sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(cleared, 0);
    db.apply_event(&event).unwrap();
    let reprojected: i64 = db
        .conn
        .query_row("select count(*) from review_sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reprojected, 1);
}

/// The acceptance join: every recorded session must be reachable from the
/// verdict that concluded it.
#[test]
fn decision_with_session_id_round_trips_and_joins() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let session = append_review_session_event(&log, "session-1", "fp3_session");
    let decision = log
        .append(
            EventKind::TriageDecided,
            "human",
            None,
            None,
            serde_json::json!({
                "stableFp": "fp3_session",
                "findingId": 7,
                "verdict": "confirmed",
                "rationale": "verified",
                "author": "human",
                "confidenceMillis": 1000,
                "reviewSessionId": "session-1",
            }),
        )
        .unwrap();

    db.apply_event(&session).unwrap();
    db.apply_event(&decision).unwrap();

    let joined: (String, String, i64) = db
        .conn
        .query_row(
            "select s.review_session_id, d.decision_verdict, s.baseline_rank
               from review_decisions d
               join review_sessions s on s.review_session_id = d.review_session_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        joined,
        ("session-1".to_string(), "confirmed".to_string(), 17)
    );
}

/// A verdict taken without shadow recording keeps a null link rather than
/// being attached to the nearest session.
#[test]
fn decision_without_session_id_projects_null() {
    let db = ProjectionDb::open_in_memory().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = append_review_decision_event(&log);

    db.apply_event(&event).unwrap();

    let session_id: Option<String> = db
        .conn
        .query_row(
            "select review_session_id from review_decisions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(session_id, None);
}

/// A projection written before sessions existed gains the table and the link
/// column on open, without disturbing the decisions already in it.
#[test]
fn legacy_projection_db_gains_review_sessions_table_and_decision_column() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("index.sqlite3");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        r#"
        create table review_decisions (
          id integer primary key autoincrement,
          finding_id integer not null,
          identity_id text,
          decision_verdict text not null,
          triage_verdict text,
          confidence real not null,
          rationale text not null,
          author text not null,
          created_at text not null,
          dismiss_reason text,
          dismissed_by text
        );
        insert into review_decisions
          (finding_id, identity_id, decision_verdict, triage_verdict, confidence,
           rationale, author, created_at, dismiss_reason, dismissed_by)
        values
          (7, null, 'confirmed', 'true_positive', 0.9, 'r', 'human',
           '2026-01-01T00:00:00Z', null, null);
        "#,
    )
    .unwrap();
    drop(conn);

    drop(ProjectionDb::open(&db_path).unwrap());

    let conn = Connection::open(&db_path).unwrap();
    assert!(table_has_column(&conn, "review_decisions", "review_session_id").unwrap());
    assert!(table_has_column(&conn, "review_sessions", "review_session_id").unwrap());
    let (verdict, session): (String, Option<String>) = conn
        .query_row(
            "select decision_verdict, review_session_id from review_decisions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(verdict, "confirmed");
    assert_eq!(session, None);
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

fn append_review_session_event(
    log: &EventLog,
    review_session_id: &str,
    stable_fp: &str,
) -> EventEnvelope {
    log.append(
        EventKind::ReviewSessionStarted,
        "operator",
        None,
        None,
        review_session_payload(review_session_id, stable_fp),
    )
    .unwrap()
}

fn review_session_payload(review_session_id: &str, stable_fp: &str) -> serde_json::Value {
    serde_json::json!({
            "reviewSessionId": review_session_id,
            "stableFp": stable_fp,
            "identityId": "fi_session",
            "findingId": 7,
            "featureSchemaId": "kuzushi-review-yield-features-v1",
            "featureSnapshotHash": "blake3:feature",
            "featureCutoffSeq": 12_000,
            "modelId": "blake3:model",
            "eligibility": "eligible",
            "baselineRank": 17,
            "shadowRank": 5,
            "queueSize": 133,
            "proofBand": "likely",
            "severity": "high",
    })
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
