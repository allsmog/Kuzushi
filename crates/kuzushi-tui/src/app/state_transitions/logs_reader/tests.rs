use super::*;
use ratatui::{backend::TestBackend, Terminal};

fn fixture() -> ShellApp {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    app.set_shell_view(ShellView::Logs);
    for index in 0..30 {
        app.log(
            "citation",
            format!("Owned inspection row {index}: unavailable source; verdict unchanged."),
        );
    }
    app.router.logs_mut().follow_tail();
    app
}

fn key(app: &mut ShellApp, code: KeyCode) -> InputUpdate {
    app.reduce_key(KeyEvent::new(code, KeyModifiers::NONE))
}

#[test]
fn logs_reader_preserves_origin_follow_state_and_unsubmitted_draft() {
    let mut app = fixture();
    key(&mut app, KeyCode::Char('z'));
    assert!(app.router.logs().reader_open());
    key(&mut app, KeyCode::PageUp);
    assert!(!app.router.logs().is_following());
    app.editor_mut().set_input("retained draft α");
    key(&mut app, KeyCode::Esc);
    assert!(!app.router.logs().reader_open());
    assert!(app.router.logs().is_following());
    assert_eq!(app.input(), "retained draft α");
}

#[test]
fn logs_reader_paste_returns_to_composer_without_submission() {
    let mut app = fixture();
    key(&mut app, KeyCode::Char('z'));
    let update = app.reduce_paste("draft α\nsecond line");
    assert!(!app.router.logs().reader_open());
    assert_eq!(app.editor().expanded_input(), "draft α\nsecond line");
    assert!(update.effects.is_empty());
}

#[test]
fn logs_reader_stays_closed_when_the_composer_owns_a_draft() {
    let mut app = fixture();
    app.editor_mut().set_input("draft");
    key(&mut app, KeyCode::Char('z'));
    assert!(!app.router.logs().reader_open());
    assert_eq!(app.input(), "draftz");
}

#[test]
fn logs_reader_uses_the_actual_expanded_page_at_every_supported_size() {
    let mut app = fixture();
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        app.set_viewport(crate::app::TerminalViewport::new(width, height));
        key(&mut app, KeyCode::Char('z'));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("READ TRANSCRIPT"));
        assert!(text.contains("Esc back"));
        assert!(text.contains("Ctrl+G palette"));
        assert!(!text.contains("z expand"));
        let reader = crate::renderer::logs_reader_scroll(&app).unwrap();
        assert!(reader.page_rows >= 6);
        assert!(text.contains("c read commands"));
        key(&mut app, KeyCode::PageUp);
        assert!(app.router.logs().scroll() <= reader.max_offset);
        key(&mut app, KeyCode::Esc);
    }
}

#[test]
fn command_disclosure_preserves_both_scrolls_follow_state_and_composer() {
    let mut app = fixture();
    app.router.logs_mut().set_scroll(7);
    app.router.logs_mut().scroll_up(0);
    key(&mut app, KeyCode::Char('z'));
    key(&mut app, KeyCode::Char('c'));
    assert!(app.router.logs().command_text_expanded());
    assert_eq!(app.router.logs().scroll(), 0);
    app.router.logs_mut().set_scroll(23);
    app.editor_mut().set_input("held α\noperator draft");
    let cursor = app.cursor();
    key(&mut app, KeyCode::Char('c'));
    assert!(!app.router.logs().command_text_expanded());
    assert_eq!(app.router.logs().scroll(), 7);
    key(&mut app, KeyCode::Char('c'));
    assert_eq!(app.router.logs().scroll(), 23);
    key(&mut app, KeyCode::Esc);
    assert!(!app.router.logs().command_text_expanded());
    assert_eq!(app.router.logs().scroll(), 7);
    assert!(!app.router.logs().is_following());
    assert_eq!(app.input(), "held α\noperator draft");
    assert_eq!(app.cursor(), cursor);
    assert!(!app.has_running_work());
}

#[test]
fn command_disclosure_does_not_own_normal_typing_or_submit_work() {
    let mut app = fixture();
    let update = key(&mut app, KeyCode::Char('c'));
    assert_eq!(app.input(), "c");
    assert!(!app.router.logs().reader_open());
    assert!(!app.router.logs().command_text_expanded());
    assert!(update.effects.is_empty());
    assert!(!app.has_running_work());
}

#[test]
fn expanded_logs_reader_yields_control_keys_to_the_command_palette() {
    let mut app = fixture();
    key(&mut app, KeyCode::Char('z'));
    let scroll = app.router.logs().scroll();
    app.reduce_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::CONTROL));
    assert_eq!(app.shell_view(), ShellView::CommandPalette);
    assert_eq!(app.router.logs().scroll(), scroll);
}

#[test]
fn foreground_scope_review_keeps_keys_from_background_logs() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = fixture();
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_shell_view(ShellView::Logs);
    app.open_scope_review();
    assert!(app.scope_review_is_visible());
    assert!(app
        .handle_logs_reader_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE))
        .is_none());
    assert!(!app.router.logs().reader_open());
    assert!(app.scope_review_is_visible());
}
