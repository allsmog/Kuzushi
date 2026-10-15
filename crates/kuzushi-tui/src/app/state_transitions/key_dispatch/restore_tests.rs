use super::*;

#[test]
fn review_backlog_keys_reach_their_actions_through_the_full_reducer() {
    for modifiers in [KeyModifiers::NONE, KeyModifiers::SHIFT] {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Review));
        app.set_input_mode(InputMode::Navigate);
        *app.findings_mut() = vec![kuzushi_core::Finding::new_tool(
            "owned-fixture",
            "owned",
            "source.rs",
            1,
            None,
            kuzushi_core::Severity::Info,
            "Owned inert observation",
        )];
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('B'), modifiers))
                .handled
        );
        assert!(app.router.workbench().review().backlog);
        app.reduce_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(
            app.router.workbench().review().backlog_tool.as_deref(),
            Some("owned-fixture")
        );
        assert!(!app.router.workbench().trace_view_open());
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app.input().is_empty());
        assert_eq!(app.router.workbench().review().session_decided, 0);
    }
}

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
