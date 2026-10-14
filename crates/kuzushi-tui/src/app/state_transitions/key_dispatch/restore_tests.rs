use super::*;

#[test]
fn reader_draft_restore_keeps_navigation_until_prompt_is_requested() {
    for encoding in ['_', '7'] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Logs);
        app.set_input("owned draft\nsecond line é");
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.reduce_key(key(KeyCode::Esc));
        assert!(app.input().is_empty());
        app.reduce_key(key(KeyCode::Esc));
        assert_eq!(app.input_mode(), InputMode::Navigate);
        app.reduce_key(key(KeyCode::Char('z')));
        app.reduce_key(key(KeyCode::Char('q')));

        let restored = app.reduce_key(KeyEvent::new(
            KeyCode::Char(encoding),
            KeyModifiers::CONTROL,
        ));

        assert!(restored.handled);
        assert_eq!(app.input(), "owned draft\nsecond line é");
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("draft restored")));
        app.reduce_key(key(KeyCode::Esc));
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert_eq!(app.input(), "owned draft\nsecond line é");
        assert_eq!(app.shell_view(), ShellView::Logs);
    }
}
