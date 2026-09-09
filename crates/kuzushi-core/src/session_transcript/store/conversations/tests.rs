use super::*;
use crate::session_transcript::{ChatTurn, ThreadContextKey};

fn snapshot(target: &Path) -> ConversationSnapshot {
    ConversationSnapshot {
        version: 1,
        context: ThreadContextKey {
            canonical_target: target.to_path_buf(),
            target_revision: "tree:revision-a".into(),
            threat_model_ref: None,
            attached_model_sha256: Some("model-digest".into()),
            policy_version: "ask-policy-v1".into(),
        },
        current: ChatTurn {
            question: "Explain the boundary".into(),
            answer: Some("Public answer".into()),
            partial_answer: String::new(),
            error: None,
        },
        history: vec![],
        run_id: "agent-test-1".into(),
        started_secs: 1,
        screen_context_scope: Some("Map Summary".into()),
        interrupted: false,
    }
}

fn write_snapshot(store: &SessionTranscriptStore, saved: ConversationSnapshot) -> PathBuf {
    let recorder = store
        .start(SessionMetadata::new(
            "test",
            &saved.context.canonical_target,
        ))
        .unwrap();
    recorder
        .record(SessionEvent::AgentConversation { snapshot: saved })
        .unwrap();
    recorder.shutdown("completed").unwrap();
    recorder.path().to_path_buf()
}

#[test]
fn recovery_round_trips_only_public_context_and_turns() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let saved = snapshot(temp.path());
    write_snapshot(&store, saved.clone());
    let actual = store
        .recover_conversation(temp.path(), Path::new("/current"))
        .unwrap();
    assert_eq!(actual, Some(saved));
    assert_eq!(
        store
            .recover_conversation(&temp.path().join("other"), Path::new("/current"))
            .unwrap(),
        None
    );
}

#[test]
fn recovery_cleared_target_never_revives_an_older_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store
        .start(SessionMetadata::new("test", temp.path()))
        .unwrap();
    recorder
        .record(SessionEvent::AgentConversation {
            snapshot: snapshot(temp.path()),
        })
        .unwrap();
    recorder
        .record(SessionEvent::AgentConversationCleared {
            target: temp.path().to_path_buf(),
        })
        .unwrap();
    recorder.shutdown("completed").unwrap();
    assert_eq!(
        store
            .recover_conversation(temp.path(), Path::new("/current"))
            .unwrap(),
        None
    );
}

#[test]
fn recovery_excludes_current_and_other_live_sessions() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store
        .start(SessionMetadata::new("test", temp.path()))
        .unwrap();
    recorder
        .record(SessionEvent::AgentConversation {
            snapshot: snapshot(temp.path()),
        })
        .unwrap();
    recorder.flush().unwrap();
    assert_eq!(
        store
            .recover_conversation(temp.path(), Path::new("/current"))
            .unwrap(),
        None
    );
    recorder.shutdown("completed").unwrap();
    assert_eq!(
        store
            .recover_conversation(temp.path(), recorder.path())
            .unwrap(),
        None
    );
}

#[test]
fn recovery_uses_the_existing_secret_redaction_before_storage() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut saved = snapshot(temp.path());
    saved.current.question = "api_key=sk-test-PRIVATE_RECOVERY_SENTINEL".into();
    let path = write_snapshot(&store, saved);
    let body = std::fs::read_to_string(path).unwrap();
    assert!(!body.contains("PRIVATE_RECOVERY_SENTINEL"));
    let actual = store
        .recover_conversation(temp.path(), Path::new("/current"))
        .unwrap()
        .unwrap();
    assert!(actual.current.question.contains("[REDACTED]"));
}

#[test]
fn recovery_refuses_malformed_or_unsupported_checkpoints() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut saved = snapshot(temp.path());
    saved.version = 2;
    let path = write_snapshot(&store, saved);
    assert!(store
        .recover_conversation(temp.path(), Path::new("/current"))
        .is_err());
    std::fs::write(path, "not a transcript\n").unwrap();
    assert!(store
        .recover_conversation(temp.path(), Path::new("/current"))
        .is_err());
}

#[test]
fn recovery_limits_history_and_encoded_bytes_without_truncating_turns() {
    let mut saved = snapshot(Path::new("/target"));
    saved.history = vec![saved.current.clone(); 13];
    assert!(saved.validate().is_err());
    saved.history.clear();
    saved.current.answer = Some("a".repeat(512 * 1024));
    assert!(saved.validate().is_err());
}

#[test]
fn recovery_refuses_partial_transcripts_and_oversize_reads() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let path = write_snapshot(&store, snapshot(temp.path()));
    let body = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{body}{{\"partial\"")).unwrap();
    assert!(store
        .recover_conversation(temp.path(), Path::new("/current"))
        .is_err());
    let mut remaining = 1;
    assert!(recovery_records(&path, &mut remaining).is_err());
}
