use super::*;
use kuzushi_core::session_transcript::SessionMetadata;

fn chat(target: &std::path::Path) -> AgentChatView {
    AgentChatView {
        question: "Explain this Map".into(),
        answer: Some("A captured public answer".into()),
        run_id: Some("agent-recovery-test".into()),
        thread_context_key: Some(ThreadContextKey {
            canonical_target: target.to_path_buf(),
            target_revision: "tree:before".into(),
            threat_model_ref: None,
            attached_model_sha256: Some("model-before".into()),
            policy_version: "policy-v1".into(),
        }),
        ..Default::default()
    }
}

#[test]
fn recovery_snapshot_preserves_binding_without_runtime_or_failure_handoff() {
    let prior = chat(std::path::Path::new("/target"));
    let restored = snapshot::restore(snapshot::capture(&prior).unwrap());
    assert_eq!(restored.question, prior.question);
    assert_eq!(restored.answer, prior.answer);
    assert_eq!(restored.thread_context_key, prior.thread_context_key);
    assert!(!restored.running);
    assert!(!restored.auxiliary_read_only);
    assert!(restored.pending_failure_context.is_none());
    assert!(restored.recovery_note.is_some());
}

#[test]
fn recovery_interrupted_turn_cannot_become_a_completed_answer() {
    let mut prior = chat(std::path::Path::new("/target"));
    prior.running = true;
    prior.partial_answer = "unfinished public text".into();
    let restored = snapshot::restore(snapshot::capture(&prior).unwrap());
    assert_eq!(restored.answer, None);
    assert_eq!(restored.partial_answer, prior.partial_answer);
    assert!(restored.error.as_deref().unwrap().contains("interrupted"));
    assert!(!restored.running);
    assert!(!restored.abort_requested);
}

#[test]
fn recovery_changed_context_resets_completed_history() {
    let restored =
        snapshot::restore(snapshot::capture(&chat(std::path::Path::new("/target"))).unwrap());
    let mut key = restored.thread_context_key.clone().unwrap();
    key.target_revision = "tree:after".into();
    let (bound, reason) = restored.bind_to_context(key);
    assert!(bound.completed_turns().is_empty());
    assert_eq!(reason.as_deref(), Some("target revision changed"));
}

fn app_with_pending(target: &std::path::Path) -> (ShellApp, mpsc::Sender<RecoveryResult>) {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.to_path_buf()));
    let (send, recv) = mpsc::channel();
    app.domain.agent_chat_state_mut().recovery.pending = Some(recv);
    (app, send)
}

fn ready(target: &std::path::Path, generation: u64) -> RecoveryResult {
    RecoveryResult {
        target: target.to_path_buf(),
        generation,
        result: Ok(snapshot::capture(&chat(target))),
    }
}

#[test]
fn recovery_preserves_focus_and_drafts_and_never_launches_work() {
    let target = std::path::Path::new("/target");
    let (mut app, send) = app_with_pending(target);
    app.router.answers_mut().draft.insert("unfinished reply 界");
    app.set_input("unfinished command");
    let view = app.shell_view();
    let focus = app.router.answers().focus;
    send.send(ready(target, app.agent_chat_generation()))
        .unwrap();
    assert!(app.apply_answer_recovery());
    assert_eq!(app.shell_view(), view);
    assert_eq!(app.router.answers().focus, focus);
    assert_eq!(app.router.answers().draft.text(), "unfinished reply 界");
    assert_eq!(app.input(), "unfinished command");
    assert!(!app.has_running_work());
}

#[test]
fn recovery_late_result_cannot_replace_new_or_cleared_state() {
    let target = std::path::Path::new("/target");
    let (mut app, send) = app_with_pending(target);
    send.send(ready(target, app.agent_chat_generation()))
        .unwrap();
    app.clear_agent_chat();
    assert!(!app.apply_answer_recovery());
    assert!(app.agent_chat().is_none());
}

#[test]
fn recovery_late_result_cannot_cross_target_switch() {
    let target = std::path::Path::new("/target");
    let (mut app, send) = app_with_pending(target);
    send.send(ready(target, app.agent_chat_generation()))
        .unwrap();
    app.set_target(Some(PathBuf::from("/other")));
    assert!(!app.apply_answer_recovery());
    assert!(app.agent_chat().is_none());
}

#[test]
fn recovery_persisted_turn_survives_a_new_shell() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let recorder = store
        .start(SessionMetadata::new("test", temp.path()))
        .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.attach_session_transcript(recorder);
    app.set_agent_chat(Some(chat(temp.path())));
    app.persist_answer_conversation();
    app.finish_session_transcript("completed");
    let saved = store
        .recover_conversation(temp.path(), std::path::Path::new("/current"))
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot::restore(saved).answer,
        app.agent_chat().unwrap().answer
    );
}

fn restarted_app(store: &SessionTranscriptStore, target: &std::path::Path) -> ShellApp {
    let recorder = store.start(SessionMetadata::new("test", target)).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.to_path_buf()));
    app.attach_session_transcript(recorder);
    app.start_answer_recovery();
    app
}

fn finish_recovery(app: &mut ShellApp) {
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < limit {
        if app.apply_answer_recovery() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("Ask recovery did not finish");
}

#[test]
fn recovery_background_restart_and_explicit_clear_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    let store = SessionTranscriptStore::from_root(temp.path().join("sessions"));
    let mut first = restarted_app(&store, temp.path());
    finish_recovery(&mut first);
    first.set_agent_chat(Some(chat(temp.path())));
    first.persist_answer_conversation();
    first.finish_session_transcript("completed");
    let mut second = restarted_app(&store, temp.path());
    finish_recovery(&mut second);
    assert_eq!(
        second.agent_chat().unwrap().answer.as_deref(),
        Some("A captured public answer")
    );
    second.handle_command(ShellCommand::Clear);
    second.finish_session_transcript("completed");
    let mut third = restarted_app(&store, temp.path());
    finish_recovery(&mut third);
    assert!(third.agent_chat().unwrap().question.is_empty());
    assert!(third
        .agent_chat()
        .unwrap()
        .recovery_note
        .as_deref()
        .unwrap()
        .contains("No recoverable"));
    third.finish_session_transcript("completed");
}

#[test]
fn recovery_late_result_cannot_replace_a_new_running_question() {
    let target = std::path::Path::new("/target");
    let (mut app, send) = app_with_pending(target);
    send.send(ready(target, app.agent_chat_generation()))
        .unwrap();
    let mut current = chat(target);
    current.question = "New explicit question".into();
    current.running = true;
    app.set_agent_chat(Some(current));
    assert!(!app.apply_answer_recovery());
    assert_eq!(app.agent_chat().unwrap().question, "New explicit question");
}

#[test]
fn recovery_keeps_a_submitted_question_until_history_is_ready() {
    let target = std::path::Path::new("/target");
    let (mut app, _send) = app_with_pending(target);
    app.domain.agent_chat_state_mut().recovery.requested = Some(target.to_path_buf());
    app.set_shell_view(ShellView::Workbench);
    let effects = app.reduce_ask_agent(&AskRequest::screen("Continue my earlier answer"));
    assert!(effects.is_empty());
    assert_eq!(
        app.router.answers().draft.text(),
        "Continue my earlier answer"
    );
    assert_eq!(app.router.answers().focus, AnswerFocus::Reply);
    assert!(!app.has_running_work());
}

#[test]
fn recovery_restores_submitted_failed_question_for_editing_without_overwriting_a_draft() {
    let target = std::path::Path::new("/target");
    let (mut app, _send) = app_with_pending(target);
    let mut saved = snapshot::capture(&chat(target)).unwrap();
    saved.interrupted = true;
    app.install_answer_snapshot(saved.clone());
    assert_eq!(app.router.answers().draft.text(), "Explain this Map");
    assert_eq!(app.router.answers().focus, AnswerFocus::Workspace);
    app.router.answers_mut().draft = FieldEditor::new("Newer unsent question");
    app.install_answer_snapshot(saved);
    assert_eq!(app.router.answers().draft.text(), "Newer unsent question");
}
