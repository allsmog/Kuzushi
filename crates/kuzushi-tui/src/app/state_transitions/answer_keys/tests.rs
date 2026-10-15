use super::*;
use crate::app::{
    AgentCallAudit, AgentChatView, AgentEvent, ChatTurn, TerminalViewport, ThreadContextKey,
};
use kuzushi_core::V2Config;
use std::path::Path;

fn app() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_viewport(TerminalViewport::new(80, 24));
    app.set_input("unfinished shell command".to_string());
    app.set_agent_chat(Some(AgentChatView {
        question: "Explain the boundary".into(),
        answer: Some((0..100).map(|n| format!("answer line {n}\n")).collect()),
        ..Default::default()
    }));
    app.open_answers();
    app
}

fn key(app: &mut ShellApp, code: KeyCode, modifiers: KeyModifiers) -> InputUpdate {
    app.reduce_key(KeyEvent::new(code, modifiers))
}

#[test]
fn answers_keep_shell_draft_while_reading_editing_and_returning_to_map() {
    let mut app = app();
    key(&mut app, KeyCode::End, KeyModifiers::NONE);
    assert!(app.router.answers().scroll.unwrap() > 0);
    key(&mut app, KeyCode::Up, KeyModifiers::NONE);
    let scroll = app.router.answers().scroll;
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.reduce_paste("AC\nδ");
    key(&mut app, KeyCode::Home, KeyModifiers::CONTROL);
    key(&mut app, KeyCode::Right, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('B'), KeyModifiers::SHIFT);
    assert_eq!(app.router.answers().draft.text(), "ABC\nδ");
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(app.router.answers().focus, AnswerFocus::Reading);
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert!(!app.router.answers().visible);
    assert_eq!(app.input(), "unfinished shell command");
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    assert_eq!(app.router.answers().scroll, scroll);
    assert_eq!(app.router.answers().draft.text(), "ABC\nδ");
}

#[test]
fn answers_typed_letters_start_a_reply_instead_of_triggering_view_actions() {
    let mut app = app();
    for ch in "jqrL".chars() {
        assert!(key(&mut app, KeyCode::Char(ch), KeyModifiers::NONE)
            .effects
            .is_empty());
    }
    key(&mut app, KeyCode::Enter, KeyModifiers::SHIFT);
    app.reduce_paste("second line");
    assert_eq!(app.router.answers().draft.text(), "jqrL\nsecond line");
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input(), "unfinished shell command");
}

#[test]
fn answers_model_refusal_is_visible_and_keeps_the_question_for_retry() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = app();
    app.set_target(Some(temp.path().to_path_buf()));
    app.config_mut().model = None;
    app.open_answers();
    app.reduce_paste("Why is this boundary trusted?");
    let update = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(update.effects.is_empty());
    assert_eq!(
        app.router.answers().draft.text(),
        "Why is this boundary trusted?"
    );
    assert!(app.agent_chat().unwrap().error.is_some());
    assert!(answer_document(&app, 76)
        .lines
        .iter()
        .any(|line| line.kind == crate::ui_view_models::AnswerLineKind::Error));
}

#[test]
fn answers_submission_without_accepted_context_keeps_draft_and_starts_no_work() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = app();
    app.set_target(Some(temp.path().to_path_buf()));
    app.config_mut().model = Some("openai:gpt-5.4".into());
    app.session_mut().mark_session_api_key_ready("openai");
    app.open_answers();
    app.reduce_paste("Explain this API");
    let update = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(update.effects.is_empty());
    assert!(app
        .agent_chat()
        .unwrap()
        .error
        .as_deref()
        .unwrap()
        .contains("Accept a current Map"));
    assert_eq!(app.router.answers().draft.text(), "Explain this API");
    assert_eq!(app.input(), "unfinished shell command");
    assert!(
        !app.has_running_work(),
        "reduction must not start the worker"
    );
}

#[test]
fn answers_completion_refreshes_cache_without_stealing_focus_or_erasing_drafts() {
    let mut app = app();
    app.agent_chat_mut().unwrap().running = true;
    let before = answer_document(&app, 76);
    app.router.answers_mut().close();
    app.router.answers_mut().draft.insert("keep this follow-up");
    let focus = app.router.answers().clone();
    app.apply_agent_event(AgentEvent::Answered {
        text: "New complete answer".into(),
        audit: AgentCallAudit::for_prompt("openai:gpt-5.4", "", ""),
    });
    assert_eq!(app.router.answers(), &focus);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    let after = answer_document(&app, 76);
    assert!(!std::sync::Arc::ptr_eq(&before, &after));
    assert!(after
        .lines
        .iter()
        .any(|line| line.content.to_string() == "New complete answer"));
    assert!(std::sync::Arc::ptr_eq(&after, &answer_document(&app, 76)));
}

#[test]
fn answers_ctrl_c_cancels_only_ask_and_modals_keep_their_keys() {
    let mut app = app();
    app.agent_chat_mut().unwrap().running = true;
    let update = key(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert!(matches!(
        update.effects.as_slice(),
        [ShellEffect::CancelJob(JobKind::Agent)]
    ));
    app.router.set_overlay_origin(Some(ShellView::Workbench));
    app.set_shell_view(ShellView::QuitConfirm);
    let state = app.router.answers().clone();
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    app.reduce_paste("must not change a hidden draft");
    assert_eq!(app.router.answers(), &state);
    assert_eq!(app.input(), "unfinished shell command");
}

fn context(target: &Path, revision: &str) -> ThreadContextKey {
    ThreadContextKey {
        canonical_target: target.to_path_buf(),
        target_revision: revision.to_string(),
        threat_model_ref: None,
        attached_model_sha256: None,
        policy_version: "test".into(),
    }
}

#[test]
fn answers_preserve_earlier_context_for_reading_without_reattaching_it() {
    let mut app = app();
    let target = Path::new("/test-target");
    app.agent_chat_mut().unwrap().thread_context_key = Some(context(target, "old-revision"));
    let prior = app.agent_chat().unwrap().clone();
    let (bound, reason) = prior.bind_to_context(context(target, "new-revision"));
    assert!(reason.is_some());
    assert!(bound.completed_turns().is_empty());
    app.set_agent_chat(Some(bound.fold_for_next_turn("new question".into())));
    assert_eq!(app.agent_chat_history().len(), 1);
    key(&mut app, KeyCode::Left, KeyModifiers::ALT);
    let older = answer_document(&app, 76);
    assert!(older.context_label.contains("old-revision"));
    assert!(older
        .lines
        .iter()
        .any(|line| line.content.to_string() == "answer line 99"));
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(app.router.answers().history, 0);
    assert!(app.agent_chat().unwrap().history.is_empty());
    assert!(app.router.answers().draft.text().is_empty());
}

#[test]
fn answers_old_turns_and_long_answers_are_exhaustive_in_plain_output() {
    let mut app = app();
    app.agent_chat_mut().unwrap().history.push(ChatTurn {
        question: "Earlier question".into(),
        answer: Some("Earlier complete answer".into()),
        error: None,
        partial_answer: String::new(),
    });
    let text = crate::renderer::render_plain_app(&app, 80);
    assert!(text.contains("Earlier complete answer"));
    assert!(text.contains("answer line 0"));
    assert!(text.contains("answer line 99"));
}

mod failure;
mod focus;
mod markdown;
mod rendering;
mod streaming;
