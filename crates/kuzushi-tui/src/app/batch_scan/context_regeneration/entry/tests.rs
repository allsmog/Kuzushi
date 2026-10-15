use super::*;
use crate::app::{InputMode, ShellView};
use crossterm::event::KeyCode;

fn app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    (root, app)
}

#[test]
fn command_opens_selection_without_model_spending_or_changing_draft() {
    let (root, mut app) = app();
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("kept\noperator draft α");
    let cursor = app.cursor();
    assert!(app.reduce_threat_regen().is_empty());
    assert_eq!(app.shell_view(), ShellView::Campaign);
    let picker = app.study_context_picker().unwrap();
    assert!(picker.regeneration_entry);
    assert!(picker.selected.is_none());
    assert!(app.context_generation().is_none());
    assert!(!app.has_running_work());
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
    app.handle_study_context_key(KeyCode::Esc);
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), "kept\noperator draft α");
    assert_eq!(app.cursor(), cursor);
}

#[test]
fn existing_study_draft_is_kept_without_starting_a_legacy_worker() {
    let (_root, mut app) = app();
    app.open_batch_scan_config(None);
    let before = app.router.campaign().batch_scan_config.clone();
    assert!(app.reduce_threat_regen().is_empty());
    assert_eq!(app.router.campaign().batch_scan_config, before);
    assert!(!app.has_running_work());
    assert!(app
        .log_lines()
        .iter()
        .any(|row| row.body.contains("Your study draft is still open")));
}

#[test]
fn active_work_keeps_focus_and_refuses_another_entry() {
    let (_root, mut app) = app();
    app.set_shell_view(ShellView::Activity);
    let ticket = app
        .jobs_mut()
        .try_start(crate::app::JobKind::Run, "owned reader")
        .unwrap();
    assert!(app.reduce_threat_regen().is_empty());
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.study_context_picker().is_none());
    assert!(app
        .log_lines()
        .iter()
        .any(|row| row.body.contains("Wait for active work")));
    app.jobs_mut().finish(crate::app::JobKind::Run);
    ticket.complete();
}

#[test]
fn regeneration_actions_never_offer_study_omission_or_acceptance() {
    let (_root, mut app) = app();
    app.open_context_regeneration_entry().unwrap();
    let actions = crate::ui_view_models::study_context::context_actions(&app);
    for key in ['a', 'm', '+', 'b'] {
        assert!(!actions.iter().any(|(code, _)| *code == KeyCode::Char(key)));
        assert!(app
            .handle_study_context_key(KeyCode::Char(key))
            .effects
            .is_empty());
        assert!(app.study_context_picker().unwrap().regeneration_entry);
    }
    assert!(actions
        .iter()
        .any(|(_, label)| *label == "g Choose text to regenerate"));
    let catalog = crate::ui_view_models::study_context::context_catalog(&app);
    assert_eq!(catalog.rows[0].label, "Choose a saved revision");
}

#[test]
fn regeneration_entry_remains_readable_across_the_viewport_matrix() {
    let (_root, mut app) = app();
    app.open_context_regeneration_entry().unwrap();
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &mut app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            text.contains("CHOOSE CONTEXT TO REGENERATE"),
            "{width}x{height}: {text}"
        );
        assert!(text.contains("e choose text"), "{width}x{height}: {text}");
        assert!(!text.contains("a use"));
    }
}
