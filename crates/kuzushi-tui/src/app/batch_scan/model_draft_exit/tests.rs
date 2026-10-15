use super::*;
use crate::app::{FieldEditor, InputMode};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use serde_json::json;

fn fixture(tool: &str) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(std::fs::canonicalize(root.path()).unwrap()));
    app.set_shell_view(ShellView::Workbench);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("composer α\nkept");
    app.set_cursor(3);
    app.open_batch_scan_config(None);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.max_provider_calls = Some(5);
    config.study.protected_review_calls = Some(2);
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some(tool.into()),
        context_input: json!({"question":"Saved question", "guidance":"Saved guidance"}),
        guidance_editor: Some(FieldEditor::new("Changed α\nquestion")),
        scroll: 4,
        show_options: true,
        ..Default::default()
    });
    (root, app)
}

#[test]
fn back_then_stay_keeps_question_cursor_limits_and_composer() {
    let (_root, mut app) = fixture("threat-model:ask");
    let generation = app.context_generation().unwrap().clone();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Discard
    );
    app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(app.context_generation(), Some(&generation));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls
        ),
        (Some(5), Some(2))
    );
    assert_eq!((app.input(), app.cursor()), ("composer α\nkept", 3));
    assert!(!app.has_running_work());
}

#[test]
fn explicit_discard_restores_navigation_and_does_not_remove_other_goal_text() {
    let (root, mut app) = fixture("pack:suggest-scopes");
    let editor = crate::app::BriefEditor::default();
    app.runtime_state
        .brief_drafts
        .insert(root.path().into(), editor.clone());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(
        app.runtime_state.brief_drafts.get(root.path()),
        Some(&editor)
    );
    assert_eq!((app.input(), app.cursor()), ("composer α\nkept", 3));
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn quit_discloses_question_loss_without_printing_private_text_and_stay_is_exact() {
    let (_root, mut app) = fixture("threat-model:ask");
    let generation = app.context_generation().unwrap().clone();
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view(), ShellView::QuitConfirm);
    let snapshot = crate::ui_view_models::quit_confirm_model(&app);
    let text = snapshot
        .sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("model study draft"));
    assert!(!text.contains("Changed α") && !text.contains("Saved question"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(app.context_generation(), Some(&generation));
    assert!(!app.has_running_work());
}

#[test]
fn retained_workflow_draft_can_go_back_but_still_needs_a_quit_warning() {
    let (_root, mut app) = fixture("planner:propose");
    let generation = app.context_generation().unwrap().clone();
    assert!(app.has_session_only_model_study_choices());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(app.router.campaign().batch_scan_config.is_none());
    assert_eq!(
        app.router
            .campaign()
            .workflow_proposal_study
            .as_ref()
            .unwrap()
            .context_generation
            .as_ref(),
        Some(&generation)
    );
    assert!(app.has_session_only_model_study_choices());
    assert!(app.resume_workflow_proposal());
    assert_eq!(app.context_generation(), Some(&generation));
}

#[test]
fn unprepared_review_requires_a_choice_before_back() {
    let (_root, mut app) = fixture("threat-model:ask");
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.context_generation = None;
    config.review_plan = Some(super::super::ReviewStudyDraft {
        input: json!({"strategy":"standard", "threatModelRef":null}),
        planning_step: None,
        scroll: 7,
        show_options: true,
    });
    let original = config.review_plan.clone();
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Discard
    );
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .review_plan,
        original
    );
    assert!(!app.has_running_work());
}

#[test]
fn question_opened_from_setup_is_not_mistaken_for_a_retained_map_draft() {
    let (_root, mut app) = fixture("threat-model:ask");
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.origin.as_mut().unwrap().view = ShellView::Setup;
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(
        app.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Discard
    );
    assert!(app.router.campaign().setup_context_study.is_none());
}

#[test]
fn discarding_embedded_context_generation_keeps_the_discovery_study() {
    let (_root, mut app) = fixture("threat-model:build");
    let input = json!({"tasks":["semgrep"], "threatModelRef":null});
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.scan_input = Some(input.clone());
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    app.reduce_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert!(config.context_generation.is_none());
    assert_eq!(config.study.scan_input, Some(input));
    assert_eq!(
        (
            config.study.max_provider_calls,
            config.study.protected_review_calls
        ),
        (Some(5), Some(2))
    );
    assert!(!app.has_running_work());
}

#[test]
fn leave_choice_keeps_loss_explanation_and_actions_visible_at_every_viewport() {
    let (_root, mut app) = fixture("threat-model:ask");
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        for required in [
            "These edits are not saved",
            "Recorded work stays unchanged",
            "Enter/Esc stay",
            "d discard choices",
        ] {
            assert!(text.contains(required), "{width}x{height}\n{text}");
        }
        assert!(!text.contains("Changed α"));
    }
}
