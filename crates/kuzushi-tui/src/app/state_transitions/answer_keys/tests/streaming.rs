use super::*;
use kuzushi_openai::langgraph_runtime::ResponseTextEvent;

fn streaming_app() -> ShellApp {
    let mut app = app();
    app.set_agent_chat(Some(AgentChatView {
        question: "Explain the boundary".into(),
        running: true,
        ..Default::default()
    }));
    app
}

fn delta(app: &mut ShellApp, text: &str) {
    let effects = app.apply_job_event(crate::app::ShellEvent::Agent(AgentEvent::ResponseText(
        ResponseTextEvent::Delta(text.into()),
    )));
    assert!(
        effects.is_empty(),
        "partial text must not persist a completed answer"
    );
}

#[test]
fn answer_stream_progress_keeps_job_running_and_preview_separate_from_answer() {
    let mut app = streaming_app();
    delta(&mut app, "First public words");
    let chat = app.agent_chat().unwrap();
    assert!(chat.running);
    assert_eq!(chat.answer, None);
    assert!(chat.completed_turns().is_empty());
    assert!(
        !crate::app::ShellEvent::Agent(AgentEvent::ResponseText(ResponseTextEvent::Reset))
            .is_terminal()
    );
    let screen = rendering::render(&mut app, 80, 24);
    assert!(screen.contains("First public words"), "{screen}");
    assert!(screen.contains("IN PROGRESS"), "{screen}");
}

#[test]
fn answer_stream_completion_replaces_preview_with_authoritative_text() {
    let mut app = streaming_app();
    delta(&mut app, "intermediate");
    app.apply_agent_event(AgentEvent::Answered {
        text: "Final answer".into(),
        audit: AgentCallAudit::test(),
    });
    let chat = app.agent_chat().unwrap();
    assert!(!chat.running);
    assert_eq!(chat.answer.as_deref(), Some("Final answer"));
    assert!(chat.partial_answer.is_empty());
    delta(&mut app, "late text");
    assert!(app.agent_chat().unwrap().partial_answer.is_empty());
}

#[test]
fn answer_stream_abort_retains_incomplete_preview_without_completed_history_output() {
    let mut app = streaming_app();
    delta(&mut app, "Unfinished source discussion");
    app.agent_chat_mut().unwrap().abort_requested = true;
    delta(&mut app, "late text");
    app.apply_agent_event(AgentEvent::Failed {
        error: "cancelled".into(),
        audit: AgentCallAudit::test(),
    });
    let chat = app.agent_chat().unwrap();
    assert_eq!(chat.partial_answer, "Unfinished source discussion");
    assert_eq!(chat.answer, None);
    let next = chat.fold_for_next_turn("Continue".into());
    assert_eq!(next.history[0].answer, None);
    assert_eq!(
        next.history[0].partial_answer,
        "Unfinished source discussion"
    );
    let screen = rendering::render(&mut app, 40, 12);
    assert!(screen.contains("INCOMPLETE"), "{screen}");
    app.set_agent_chat(Some(next));
    let plain = crate::renderer::answer_plain_lines(&app, 80).join("\n");
    assert!(plain.contains("INCOMPLETE RESPONSE"));
    assert!(plain.contains("Unfinished source discussion"));
}

#[test]
fn answer_stream_reset_discards_previous_model_attempt_preview() {
    let mut app = streaming_app();
    delta(&mut app, "first attempt");
    app.apply_agent_event(AgentEvent::ResponseText(ResponseTextEvent::Reset));
    delta(&mut app, "retry");
    assert_eq!(app.agent_chat().unwrap().partial_answer, "retry");
}

#[test]
fn answer_stream_follows_new_text_until_operator_scrolls_and_preserves_focus_and_drafts() {
    let mut app = streaming_app();
    delta(
        &mut app,
        &(0..50).map(|n| format!("line {n}\n\n")).collect::<String>(),
    );
    let doc = answer_document(&app, 74);
    assert_eq!(
        crate::ui_view_models::answer_scroll_start(&app, &doc, 5),
        doc.lines.len() - 5
    );
    rendering::render(&mut app, 80, 24);
    key(&mut app, KeyCode::Home, KeyModifiers::NONE);
    let scroll = app.router.answers().scroll;
    key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    app.reduce_paste("Held reply 東京");
    let focus = app.router.answers().focus;
    delta(&mut app, "new tail");
    assert_eq!(app.router.answers().scroll, scroll);
    assert_eq!(app.router.answers().focus, focus);
    assert_eq!(app.router.answers().draft.text(), "Held reply 東京");
    assert_eq!(app.input(), "unfinished shell command");
}
