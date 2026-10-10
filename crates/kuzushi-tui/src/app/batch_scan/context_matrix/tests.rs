use super::*;
use crate::app::{InputMode, ShellView};
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;

mod allowance;
mod results;

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned source, never executed\nfn main() {}\n",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.open_batch_scan_config(None);
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.matrix.cases = vec![
        ContextCaseInput {
            id: "alpha".into(),
            label: "Alpha".into(),
            passes: 3,
            threat_model_ref: json!({"modelId":"alpha"}),
        },
        ContextCaseInput {
            id: "beta".into(),
            label: "Beta".into(),
            passes: 3,
            threat_model_ref: json!({"modelId":"beta"}),
        },
    ];
    config.study.matrix.baseline_case_id = Some("alpha".into());
    config.study.max_provider_calls = Some(8);
    config.study.protected_review_calls = Some(2);
    app.open_context_matrix();
    (root, app)
}

#[test]
fn case_pass_editing_is_local_and_preserves_spending_and_composer_ownership() {
    let (_root, mut app) = fixture();
    app.set_input("kept draft");
    app.set_cursor(3);
    assert!(app
        .handle_context_matrix_key(KeyCode::Down)
        .unwrap()
        .effects
        .is_empty());
    assert!(app
        .handle_context_matrix_key(KeyCode::Char('p'))
        .unwrap()
        .effects
        .is_empty());
    app.handle_batch_config_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
    app.handle_batch_config_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    let config = app.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.study.matrix.cases[0].passes, 3);
    assert_eq!(config.study.matrix.cases[1].passes, 1);
    assert_eq!(config.study.matrix.planned_jobs(), 4);
    assert_eq!(config.study.max_provider_calls, Some(8));
    assert_eq!(config.study.protected_review_calls, Some(2));
    assert_eq!(
        config.study.matrix.baseline_case_id.as_deref(),
        Some("alpha")
    );
    assert!(config.study.plan_identity().is_none());
    assert_eq!((app.input(), app.cursor()), ("kept draft", 3));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(app.input_mode(), InputMode::Navigate);
}

#[test]
fn selected_case_and_all_controls_are_visible_at_the_existing_viewport_sizes() {
    use ratatui::{backend::TestBackend, Terminal};
    let (_root, mut app) = fixture();
    app.handle_context_matrix_key(KeyCode::Down);
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        for text in ["CONTEXT CASES", "Beta", "p passes", "L next", "Esc back"] {
            assert!(screen.contains(text), "{width}x{height}: {text}: {screen}");
        }
    }
}
