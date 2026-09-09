use super::*;
use crate::app::{record_agent_run_started, EffectRuntime, PlanEvent, ThreatPatchEvent};
use kuzushi_core::runtime::{
    RuntimeCostReport, RuntimeFailure, RuntimeFailureClass as Class, RuntimeFailureMetadata,
};

fn failure_audit(class: Class, status: u16) -> AgentCallAudit {
    AgentCallAudit::test()
        .with_outcome(RuntimeCostReport::INCOMPLETE_ZERO, true)
        .with_failure(
            &anyhow::Error::new(RuntimeFailure::new(RuntimeFailureMetadata::new(
                class,
                Some(status),
                Some("PRIVATE_SOURCE"),
            )))
            .context("private adapter diagnostic"),
        )
}

fn failing_app(target: &Path) -> ShellApp {
    let mut app = app();
    app.set_target(Some(target.to_path_buf()));
    app.config_mut().model = Some("openai:operator-selected".to_string());
    app.set_shell_view(ShellView::Workbench);
    app.set_agent_chat(Some(AgentChatView {
        question: "Explain the boundary".to_string(),
        running: true,
        run_id: Some("agent-recovery".to_string()),
        ..Default::default()
    }));
    app.set_agent_artifact_target(Some(target.to_path_buf()));
    app.open_answers();
    app
}

fn reject(app: &mut ShellApp) -> Vec<ShellEffect> {
    app.apply_agent_event(AgentEvent::Failed {
        error: "PRIVATE_SOURCE response hidden".to_string(),
        audit: failure_audit(Class::ProviderRejected, 400),
    })
}

#[test]
fn answers_failure_keeps_http_cause_draft_focus_model_and_cost_truth() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    let effects = reject(&mut app);
    assert!(matches!(
        effects.as_slice(),
        [ShellEffect::RecordAgentRun(_)]
    ));
    assert_eq!(app.router.answers().focus, AnswerFocus::Reading);
    assert_eq!(app.router.answers().draft.text(), "Explain the boundary");
    assert_eq!(
        app.config().model.as_deref(),
        Some("openai:operator-selected")
    );
    assert!(!app.agent_chat().unwrap().running);
    let message = app.agent_chat().unwrap().error.as_deref().unwrap();
    assert!(message.contains("Provider rejected the request (HTTP 400)."));
    assert!(message.contains("Next: Check the selected model with /model"));
    assert!(message.contains("Details: /trace agent-recovery"));
    assert!(!message.contains("PRIVATE_SOURCE"));
    let ShellEffect::RecordAgentRun(record) = &effects[0] else {
        unreachable!()
    };
    assert!(!record.audit.settlement_cost().is_complete());
    assert!(record.audit.call_attempted);
}

#[test]
fn answers_failure_summary_persists_the_same_http_cause_without_raw_text() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    record_agent_run_started(
        Some(tmp.path()),
        "agent-recovery",
        &serde_json::json!({}),
        "openai:operator-selected".to_string(),
        None,
        Vec::new(),
    )
    .unwrap();
    let effects = reject(&mut app);
    EffectRuntime::execute(&mut app, effects);
    let summary = kuzushi_core::load_run_summary(tmp.path(), "agent-recovery").unwrap();
    assert_eq!(summary.status, "failed");
    assert_eq!(
        summary.error.as_deref(),
        Some("Provider rejected the request (HTTP 400).")
    );
    assert_eq!(summary.model.as_deref(), Some("openai:operator-selected"));
    for leaf in ["result.json", "failures.json", "run.json"] {
        let text =
            std::fs::read_to_string(kuzushi_core::run_dir(tmp.path(), "agent-recovery").join(leaf))
                .unwrap();
        assert!(!text.contains("PRIVATE_SOURCE"), "{leaf}");
    }
}

#[test]
fn answers_failure_never_replaces_a_newer_draft_or_reopens_focus() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    app.reduce_paste("A newer question\nwith another line");
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    reject(&mut app);
    assert_eq!(app.router.answers().focus, AnswerFocus::Workspace);
    assert_eq!(
        app.router.answers().draft.text(),
        "A newer question\nwith another line"
    );
}

#[test]
fn answers_failure_after_cancellation_does_not_offer_unrelated_provider_repair() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    app.agent_chat_mut().unwrap().abort_requested = true;
    let effects = reject(&mut app);
    let message = app.agent_chat().unwrap().error.as_deref().unwrap();
    assert_eq!(
        message,
        "Ask canceled. Review the question before sending it again."
    );
    assert!(!message.contains("/setup"));
    let ShellEffect::RecordAgentRun(record) = &effects[0] else {
        unreachable!()
    };
    assert!(matches!(
        record.outcome,
        crate::app::AgentRunOutcome::Canceled { .. }
    ));
}

#[test]
fn answers_failure_palette_recovery_preserves_the_question_and_focuses_command_arguments() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    reject(&mut app);
    key(&mut app, KeyCode::Char('g'), KeyModifiers::CONTROL);
    assert_eq!(app.shell_view(), ShellView::CommandPalette);
    key(&mut app, KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(app.router.answers().focus, AnswerFocus::Reading);
    assert_eq!(app.router.answers().draft.text(), "Explain the boundary");

    key(&mut app, KeyCode::Char('g'), KeyModifiers::CONTROL);
    for ch in "trace".chars() {
        key(&mut app, KeyCode::Char(ch), KeyModifiers::NONE);
    }
    let update = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(update.effects.is_empty());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.answers().focus, AnswerFocus::Workspace);
    assert!(app.input().starts_with("trace"));
    assert_eq!(app.router.answers().draft.text(), "Explain the boundary");
    key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
    assert_eq!(app.router.answers().focus, AnswerFocus::Reading);
}

#[test]
fn answers_failure_setup_navigation_does_not_send_or_erase_the_question() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    reject(&mut app);
    key(&mut app, KeyCode::Char('g'), KeyModifiers::CONTROL);
    for ch in "setup".chars() {
        key(&mut app, KeyCode::Char(ch), KeyModifiers::NONE);
    }
    let update = key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert!(update
        .effects
        .iter()
        .all(|effect| !matches!(effect, ShellEffect::DispatchAgent(_))));
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert_eq!(app.router.answers().draft.text(), "Explain the boundary");
    assert_eq!(
        app.config().model.as_deref(),
        Some("openai:operator-selected")
    );
}

#[test]
fn answers_failure_trace_and_replay_reopen_the_retained_question() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    reject(&mut app);
    for view in [ShellView::Trace, ShellView::Replay] {
        app.set_shell_view(view);
        app.router.answers_mut().focus = AnswerFocus::Workspace;
        let screen = super::rendering::render(&mut app, 80, 24);
        assert!(screen.contains("Ctrl+T read / reply"));
        key(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
        assert_eq!(app.router.answers().focus, AnswerFocus::Reading);
        assert!(super::rendering::render(&mut app, 80, 24).contains("HTTP 400"));
        key(&mut app, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.router.answers().draft.text(), "Explain the boundary");
    }
}

#[test]
fn answers_failure_settings_and_modals_never_advertise_an_inactive_answer_shortcut() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    reject(&mut app);
    for view in [
        ShellView::Setup,
        ShellView::Auth,
        ShellView::Health,
        ShellView::CommandPalette,
        ShellView::QuitConfirm,
    ] {
        app.set_shell_view(view);
        app.router.set_overlay_origin(Some(ShellView::Workbench));
        assert!(!crate::ui_view_models::answers_visible(&app));
        assert!(!crate::ui_view_models::answers_own_input(&app));
        assert_eq!(app.router.answers().draft.text(), "Explain the boundary");
    }
}

#[test]
fn answers_failure_guidance_is_readable_at_ordinary_terminal_sizes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = failing_app(tmp.path());
    reject(&mut app);
    for (width, height) in [(80, 24), (120, 36), (160, 48)] {
        key(&mut app, KeyCode::Home, KeyModifiers::NONE);
        let first = super::rendering::render(&mut app, width, height);
        key(&mut app, KeyCode::End, KeyModifiers::NONE);
        let last = super::rendering::render(&mut app, width, height);
        let screens = format!("{first}\n{last}");
        assert!(screens.contains("HTTP 400"), "{width}×{height}\n{screens}");
        assert!(screens.contains("Next:"), "{width}×{height}\n{screens}");
        assert!(screens.contains("/model"), "{width}×{height}\n{screens}");
        assert!(
            screens.contains("/trace agent-recovery"),
            "{width}×{height}\n{screens}"
        );
        assert!(!screens.contains("PRIVATE_SOURCE"));
    }
}

#[test]
fn model_failure_planner_and_threat_notices_preserve_provider_causes() {
    let mut app = app();
    app.apply_plan_event(PlanEvent::Failed {
        error: "private response".to_string(),
        audit: failure_audit(Class::Authentication, 401),
    });
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("HTTP 401")
            && line.body.contains("/auth to check credentials")));
    app.apply_threat_patch_event(ThreatPatchEvent::Failed {
        error: "private response".to_string(),
        audit: failure_audit(Class::ProviderUnavailable, 503),
    });
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("HTTP 503") && line.body.contains("Wait for the provider")));
    assert!(app
        .log_lines()
        .iter()
        .all(|line| !line.body.contains("private response")));
}
