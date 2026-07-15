use super::*;
use std::fs::{self, FileTimes, OpenOptions};
use std::io::Write;
use std::time::{Duration, SystemTime};

fn metadata(mode: &str) -> SessionMetadata {
    SessionMetadata::new(mode, "/tmp/workspace")
}

#[test]
fn transcript_records_semantic_events_and_completion() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut launch = metadata("plain");
    launch.initial_target = Some("/tmp/target".into());
    launch.target_source = Some("global_flag".to_string());
    let recorder = store.start(launch).unwrap();
    let session_id = recorder.session_id().to_string();

    recorder
        .record(SessionEvent::CommandSubmitted {
            command: "scan".to_string(),
        })
        .unwrap();
    recorder
        .record(SessionEvent::RunStarted {
            run_id: "run-1".to_string(),
            tool_name: "sast:scan".to_string(),
        })
        .unwrap();
    recorder.shutdown("normal").unwrap();

    let read = store.read(&session_id).unwrap();
    assert_eq!(read.records[0].event_type, "session_meta");
    assert_eq!(read.records[1].event_type, "command_submitted");
    assert_eq!(read.summary.status, SessionStatus::Completed);
    assert_eq!(read.summary.current_target, Some("/tmp/target".into()));
    assert!(read.raw_jsonl.ends_with('\n'));
    assert_eq!(store.list(&SessionListOptions::default()).unwrap().len(), 1);
}

#[test]
fn oversized_launch_arguments_preserve_the_session_meta_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut launch = metadata("plain");
    launch.argv = vec!["x".repeat(MAX_SESSION_RECORD_BYTES * 2)];
    let recorder = store.start(launch).unwrap();
    let session_id = recorder.session_id().to_string();
    recorder.shutdown("normal").unwrap();

    let read = store.read(&session_id).unwrap();
    assert_eq!(read.records[0].event_type, "session_meta");
    assert!(read.records[0].payload["argv"]
        .as_array()
        .unwrap()
        .iter()
        .any(|argument| argument.as_str().is_some_and(|value| value.contains("[TRUNCATED argv"))));
    assert!(read
        .raw_jsonl
        .lines()
        .all(|line| line.len() <= MAX_SESSION_RECORD_BYTES));
}

#[test]
fn target_history_remains_filterable_after_switch_and_clear() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let recorder = store.start(metadata("interactive")).unwrap();
    for target in [&first, &second] {
        recorder
            .record(SessionEvent::TargetActivated {
                target: target.clone(),
                source: "picker".to_string(),
            })
            .unwrap();
    }
    recorder
        .record(SessionEvent::TargetCleared {
            source: "operator".to_string(),
        })
        .unwrap();
    recorder.shutdown("normal").unwrap();

    assert_eq!(store.read(recorder.session_id()).unwrap().summary.current_target, None);
    for target in [first, second] {
        let matches = store
            .list(&SessionListOptions {
                target: Some(target),
            })
            .unwrap();
        assert_eq!(matches.len(), 1);
    }
}

#[test]
fn secrets_are_redacted_across_typed_and_freeform_surfaces() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut launch = metadata("interactive");
    launch.argv = vec![
        "kuzushi".to_string(),
        "--api-key".to_string(),
        "argv-sentinel-secret".to_string(),
    ];
    launch.git = Some(SessionGitMetadata {
        branch: None,
        commit: None,
        dirty: None,
        remote: Some("https://alice:remote-secret@example.test/repo".to_string()),
    });
    let recorder = store.start(launch).unwrap();
    let session_id = recorder.session_id().to_string();
    recorder
        .record(SessionEvent::CommandSubmitted {
            command: "scan token=command-sentinel-secret Authorization: Basic header-secret"
                .to_string(),
        })
        .unwrap();
    recorder
        .record(SessionEvent::OperatorAnswer {
            question_id: "q1".to_string(),
            kind: "credential_request".to_string(),
            outcome: "provided".to_string(),
            answer: Some("answer-sentinel-secret".to_string()),
        })
        .unwrap();
    recorder
        .record(SessionEvent::OperatorQuestion {
            question_id: "q2".to_string(),
            kind: "credential_prompt".to_string(),
            prompt: Some("first line\ncredential-question-sentinel".to_string()),
        })
        .unwrap();
    recorder.shutdown("normal").unwrap();

    let read = store.read(&session_id).unwrap();
    let raw = &read.raw_jsonl;
    for secret in [
        "argv-sentinel-secret",
        "remote-secret",
        "command-sentinel-secret",
        "header-secret",
        "answer-sentinel-secret",
        "credential-question-sentinel",
    ] {
        assert!(!raw.contains(secret), "leaked {secret}");
    }
    assert!(raw.contains("[REDACTED]"));
    for record in read
        .records
        .iter()
        .filter(|record| matches!(record.event_type.as_str(), "operator_question" | "operator_answer"))
    {
        let content = record
            .payload
            .get("prompt")
            .or_else(|| record.payload.get("answer"));
        assert!(content.is_none_or(serde_json::Value::is_null), "{:?}", record.payload);
    }
}

#[test]
fn target_filter_matches_any_target_touched_by_a_session() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut launch = metadata("plain");
    launch.initial_target = Some("/target/one".into());
    let recorder = store.start(launch).unwrap();
    recorder
        .record(SessionEvent::TargetActivated {
            target: "/target/two".into(),
            source: "command".to_string(),
        })
        .unwrap();
    recorder
        .record(SessionEvent::TargetActivated {
            target: "/target/three".into(),
            source: "command".to_string(),
        })
        .unwrap();
    recorder.shutdown("normal").unwrap();

    let matches = store
        .list(&SessionListOptions {
            target: Some("/target/two".into()),
        })
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].current_target, Some("/target/three".into()));
}

#[test]
fn oversized_event_becomes_a_digest_backed_truncation_record() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store.start(metadata("plain")).unwrap();
    let session_id = recorder.session_id().to_string();
    recorder
        .record(SessionEvent::AgentAssistantTurn {
            text: "x".repeat(MAX_SESSION_RECORD_BYTES + 8_192),
        })
        .unwrap();
    recorder.shutdown("normal").unwrap();

    let read = store.read(&session_id).unwrap();
    let truncated = &read.records[1];
    assert_eq!(truncated.event_type, "truncated");
    assert_eq!(
        truncated.payload["originalType"],
        serde_json::Value::String("agent_assistant_turn".to_string())
    );
    assert_eq!(truncated.payload["digest"].as_str().unwrap().len(), 64);
    let mut original = truncated.clone();
    original.event_type = "agent_assistant_turn".to_string();
    original.payload = serde_json::json!({
        "text": "x".repeat(MAX_SESSION_RECORD_BYTES + 8_192)
    });
    assert_eq!(
        truncated.payload["originalBytes"].as_u64().unwrap(),
        serde_json::to_vec(&original).unwrap().len() as u64
    );
    assert!(read
        .raw_jsonl
        .lines()
        .all(|line| line.len() <= MAX_SESSION_RECORD_BYTES));
}

#[test]
fn incomplete_final_line_is_skipped_with_a_warning() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store.start(metadata("plain")).unwrap();
    let session_id = recorder.session_id().to_string();
    recorder.shutdown("normal").unwrap();
    OpenOptions::new()
        .append(true)
        .open(recorder.path())
        .unwrap()
        .write_all(b"{")
        .unwrap();

    let read = store.read(&session_id).unwrap();
    assert_eq!(read.summary.status, SessionStatus::Completed);
    assert_eq!(read.warnings.len(), 1);
    assert!(read.warnings[0].contains("incomplete"));
}

#[test]
fn malformed_middle_line_preserves_later_records_and_reports_the_gap() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store.start(metadata("plain")).unwrap();
    let session_id = recorder.session_id().to_string();
    recorder
        .record(SessionEvent::CommandSubmitted {
            command: "scan".to_string(),
        })
        .unwrap();
    recorder.shutdown("normal").unwrap();
    let original = fs::read_to_string(recorder.path()).unwrap();
    let lines = original.lines().collect::<Vec<_>>();
    fs::write(
        recorder.path(),
        format!("{}\n{{invalid\n{}\n", lines[0], lines[2]),
    )
    .unwrap();

    let read = store.read(&session_id).unwrap();
    assert_eq!(read.summary.status, SessionStatus::Completed);
    assert_eq!(read.records.len(), 2);
    assert!(read
        .warnings
        .iter()
        .any(|warning| warning.contains("invalid JSON")));
    assert!(read
        .warnings
        .iter()
        .any(|warning| warning.contains("sequence gap")));
}

#[test]
fn missing_end_from_a_dead_process_is_interrupted() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut launch = metadata("scripted");
    launch.process_id = u32::MAX;
    launch.process_start_token = None;
    let recorder = store.start(launch).unwrap();
    let session_id = recorder.session_id().to_string();
    recorder.flush().unwrap();
    drop(recorder);

    assert_eq!(
        store.read(&session_id).unwrap().summary.status,
        SessionStatus::Interrupted
    );
}

#[test]
fn pruning_removes_expired_interrupted_sessions_and_skips_live_ones() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let dead = unfinished_session(&store, u32::MAX);
    let live = unfinished_session(&store, std::process::id());
    make_old(&dead);
    make_old(&live);

    let report = store
        .prune(&SessionPruneOptions {
            older_than_days: 30,
            dry_run: false,
        })
        .unwrap();
    assert!(report.removed.contains(&dead));
    assert!(live.exists());
    assert_eq!(report.skipped_live.len(), 1);
}

#[test]
fn pruning_expires_old_malformed_regular_files() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store.start(metadata("plain")).unwrap();
    recorder.shutdown("normal").unwrap();
    let path = recorder.path().to_path_buf();
    fs::write(&path, "not-json\n").unwrap();
    make_old(&path);

    let report = store
        .prune(&SessionPruneOptions {
            older_than_days: 30,
            dry_run: false,
        })
        .unwrap();
    assert!(report.removed.contains(&path));
    assert!(!path.exists());
    assert!(report
        .errors
        .iter()
        .any(|error| error.contains("no readable records")));
}

fn unfinished_session(store: &SessionTranscriptStore, process_id: u32) -> std::path::PathBuf {
    let mut launch = metadata("plain");
    launch.process_id = process_id;
    if process_id != std::process::id() {
        launch.process_start_token = None;
    }
    let recorder = store.start(launch).unwrap();
    recorder.flush().unwrap();
    let path = recorder.path().to_path_buf();
    drop(recorder);
    path
}

fn make_old(path: &std::path::Path) {
    let old = SystemTime::now() - Duration::from_secs(31 * 86_400);
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.set_times(FileTimes::new().set_modified(old)).unwrap();
}

#[cfg(unix)]
#[test]
fn creates_private_directories_and_file() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("sessions");
    let store = SessionTranscriptStore::from_root(&root);
    let recorder = store.start(metadata("plain")).unwrap();
    recorder.flush().unwrap();

    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(recorder.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for ancestor in recorder.path().parent().unwrap().ancestors().take(3) {
        assert_eq!(
            fs::metadata(ancestor).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[cfg(unix)]
#[test]
fn refuses_a_symlinked_session_root() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("elsewhere");
    fs::create_dir(&destination).unwrap();
    let root = temp.path().join("sessions");
    std::os::unix::fs::symlink(&destination, &root).unwrap();

    let error = SessionTranscriptStore::from_root(root)
        .start(metadata("plain"))
        .err()
        .expect("symlinked root must fail");
    assert!(error.to_string().contains("symlink"));
}

#[cfg(unix)]
#[test]
fn refuses_a_symlinked_kuzushi_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let destination = temp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&destination).unwrap();
    std::os::unix::fs::symlink(&destination, home.join(".kuzushi")).unwrap();

    let error = SessionTranscriptStore::for_home(home)
        .start(metadata("plain"))
        .err()
        .expect("symlinked .kuzushi must fail");
    assert!(error.to_string().contains("symlink"));
}
