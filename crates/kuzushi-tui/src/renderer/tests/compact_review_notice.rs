use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn review_reader(mode: crate::InputMode) -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().into()));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.set_findings(vec![Finding::new_tool(
        "owned-metadata",
        "owned.marker",
        "hello.txt",
        1,
        None,
        Severity::Info,
        "Labeled owned observation. No defect is claimed.",
    )]);
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewDetail);
    app.set_input_mode(mode);
    app.set_viewport(crate::TerminalViewport::new(40, 12));
    app.set_warn_notice(
        "tool",
        "Partial result: recorded coverage is incomplete; inspect the source receipt.",
    );
    (root, app)
}

fn render(app: &ShellApp) -> String {
    let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    rendered_buffer_rows(terminal.backend().buffer()).join("\n")
}

#[test]
fn an_empty_composer_keeps_the_selected_observation_visible_beside_a_warning() {
    for mode in [crate::InputMode::Prompt, crate::InputMode::Navigate] {
        let (_root, app) = review_reader(mode);
        let area = Rect::new(0, 0, 40, 12);
        let text = render(&app);
        assert_eq!(notice_banner_height(&app, area), 1, "{mode:?}: {text}");
        assert!(primary_body_area(&app, area).height >= 7, "{text}");
        assert!(text.contains("F-0001"), "{text}");
        assert!(text.contains("Labeled owned"), "{text}");
        assert!(text.contains("Esc dismiss"), "{text}");
        assert!(text.contains("logs"), "{text}");
        assert_eq!(app.input_mode(), mode);
        assert!(app.input().is_empty());
    }
}

#[test]
fn dismissing_the_warning_preserves_input_owner_and_finding() {
    let (_root, mut app) = review_reader(crate::InputMode::Prompt);
    let before = app.findings()[0].clone();
    let update = app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    EffectRuntime::execute(&mut app, update.effects);
    assert!(app.advisory().notice.is_none());
    assert_eq!(app.input_mode(), crate::InputMode::Prompt);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.findings()[0], before);
    assert_eq!(
        app.router.workbench().focus_for(WorkbenchPage::Review),
        PhaseSurfaceId::ReviewDetail
    );
}

#[test]
fn drafts_and_running_work_retain_their_full_chrome_contract() {
    let (_root, mut app) = review_reader(crate::InputMode::Prompt);
    app.set_input("held operator draft");
    assert!(!crate::ui_view_models::compact_review_reading(&app, 12));
    assert_eq!(notice_banner_height(&app, Rect::new(0, 0, 40, 12)), 3);
    assert_eq!(app.input(), "held operator draft");
    app.set_input("");
    app.set_running_tool_for_test("context:build");
    assert!(!crate::ui_view_models::compact_review_reading(&app, 12));
    assert!(crate::ui_view_models::footer_keybindings(&app)
        .iter()
        .any(|key| key.key == "Ctrl+C" && key.label.contains("abort")));
}
