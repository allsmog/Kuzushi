use super::*;
use crate::ChatTurn;
use kuzushi_core::V2Config;

#[test]
fn agent_chat_model_reports_empty_state_and_model_label() {
    let app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-5.2".to_string()),
            ..V2Config::default()
        },
        None,
    );

    let model = agent_chat_model(&app);

    assert_eq!(model.model, "openai:gpt-5.2");
    assert!(model.session.is_none());
}

#[test]
fn agent_chat_model_copies_active_turn_and_history() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.agent_chat = Some(AgentChatView {
        question: "what now?".to_string(),
        answer: Some("run context".to_string()),
        running: false,
        abort_requested: false,
        error: None,
        history: vec![ChatTurn {
            question: "first?".to_string(),
            answer: Some("scan".to_string()),
            error: None,
        }],
        run_id: None,
        started_secs: 0,
        screen_context_scope: Some("scope: F-0001 · 作 confirm · abc1234-dirty".to_string()),
        failure_context: None,
        pending_failure_context: None,
    });

    let model = agent_chat_model(&app);
    let session = model.session.expect("agent session");

    assert_eq!(session.status, "answered");
    assert_eq!(session.question, "what now?");
    assert_eq!(session.answer, Some("run context".to_string()));
    assert_eq!(
        session.screen_context_scope.as_deref(),
        Some("scope: F-0001 · 作 confirm · abc1234-dirty")
    );
    assert_eq!(
        session.history,
        vec![AgentChatTurn {
            question: "first?".to_string(),
            answer: Some("scan".to_string()),
            error: None,
        }]
    );
}

#[test]
fn agent_chat_model_prefers_abort_status() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.agent_chat = Some(AgentChatView {
        question: "stop?".to_string(),
        answer: None,
        running: true,
        abort_requested: true,
        error: Some("late error".to_string()),
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        screen_context_scope: None,
        failure_context: None,
        pending_failure_context: None,
    });

    let session = agent_chat_model(&app).session.expect("agent session");

    assert_eq!(session.status, "abort requested");
}
