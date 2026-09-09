use super::*;
use crate::app::{
    OperatorQuestion, OperatorQuestionEnvelope, OperatorQuestionRequest, PendingOperatorQuestion,
    WorkerGeneration,
};
use std::sync::mpsc::sync_channel;

#[test]
fn answers_drafts_stay_with_their_target_and_return_on_switch_back() {
    let mut app = app();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    app.set_target(Some(first.path().to_path_buf()));
    app.open_answers();
    app.reduce_paste("Question about first target");
    app.set_target(Some(second.path().to_path_buf()));
    assert!(!app.router.answers().visible);
    assert!(app.router.answers().draft.text().is_empty());
    assert!(app.router.answers().has_drafts());
    app.open_answers();
    app.reduce_paste("Question about second target");
    app.set_target(Some(first.path().to_path_buf()));
    assert_eq!(
        app.router.answers().draft.text(),
        "Question about first target"
    );
    app.set_target(Some(second.path().to_path_buf()));
    assert_eq!(
        app.router.answers().draft.text(),
        "Question about second target"
    );
    app.clear_agent_chat();
    assert!(!app.router.answers().has_drafts());
}

#[test]
fn answers_operator_question_owns_both_keys_and_paste_until_closed() {
    let mut app = app();
    let (control, _receiver) = sync_channel(8);
    let mut session = crate::ActivitySession::new("question-run");
    session.operator_question = Some(PendingOperatorQuestion::new(OperatorQuestionEnvelope {
        request: OperatorQuestionRequest {
            request_id: "question".into(),
            run_id: "question-run".into(),
            questions: vec![OperatorQuestion {
                id: "scope".into(),
                header: "Scope".into(),
                prompt: "Which part?".into(),
                options: vec![crate::app::OperatorQuestionOption {
                    label: "Current scope".into(),
                    description: "Inspect the selected component".into(),
                    recommended: true,
                }],
            }],
            auto_resolution_ms: None,
        },
        generation: WorkerGeneration::new(1),
        control,
    }));
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    let draft = app.router.answers().draft.clone();
    assert!(!crate::ui_view_models::answers_own_input(&app));
    assert!(app.reduce_paste("Selected scope α").effects.is_empty());
    key(&mut app, KeyCode::Char('B'), KeyModifiers::SHIFT);
    let card = app.activity().unwrap().operator_question.as_ref().unwrap();
    assert_eq!(card.other_editor(), Some("Selected scope αB"));
    assert_eq!(app.router.answers().draft, draft);
    app.set_shell_view(ShellView::Workbench);
    app.reduce_paste("Ask follow-up");
    assert_eq!(app.router.answers().draft.text(), "Ask follow-up");
    let card = app.activity().unwrap().operator_question.as_ref().unwrap();
    assert_eq!(card.other_editor(), Some("Selected scope αB"));
}

#[test]
fn answers_draft_clears_only_after_the_matching_question_is_admitted() {
    let mut app = app();
    app.reduce_paste("Ready question");
    app.router.answers_mut().submitted("Different question");
    assert_eq!(app.router.answers().draft.text(), "Ready question");
    app.router.answers_mut().submitted("Ready question");
    assert!(app.router.answers().draft.text().is_empty());
}

#[test]
fn answers_runtime_failure_restores_retry_text_without_erasing_new_drafts_or_changing_focus() {
    for existing in ["", "A new question while waiting"] {
        let mut app = app();
        app.router.answers_mut().draft.insert(existing);
        app.router.answers_mut().close();
        app.agent_chat_mut().unwrap().running = true;
        app.apply_agent_event(AgentEvent::Failed {
            error: "unexpected adapter failure".into(),
            audit: AgentCallAudit::for_prompt("openai:gpt-5.4", "", ""),
        });
        let expected = if existing.is_empty() {
            "Explain the boundary"
        } else {
            existing
        };
        assert_eq!(app.router.answers().draft.text(), expected);
        assert!(!app.router.answers().visible);
        assert_eq!(app.router.answers().focus, AnswerFocus::Workspace);
        assert_eq!(app.input(), "unfinished shell command");
    }
}

#[test]
fn answers_late_failure_keeps_its_draft_with_the_dispatch_target() {
    let mut app = app();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    app.set_target(Some(first.path().to_path_buf()));
    app.set_agent_artifact_target(Some(first.path().to_path_buf()));
    app.set_target(Some(second.path().to_path_buf()));
    app.router
        .answers_mut()
        .draft
        .insert("Second-target question");
    app.apply_agent_event(AgentEvent::Failed {
        error: "unexpected adapter failure".into(),
        audit: AgentCallAudit::for_prompt("openai:gpt-5.4", "", ""),
    });
    assert_eq!(app.router.answers().draft.text(), "Second-target question");
    app.set_target(Some(first.path().to_path_buf()));
    assert_eq!(app.router.answers().draft.text(), "Explain the boundary");
}
