#[cfg(test)]
mod tests {
    use super::super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use std::sync::mpsc;

    #[test]
    fn plain_shell_detection_covers_forced_non_tty_and_tty_modes() {
        assert!(should_run_plain_shell_for_io(true, true, true, false));
        assert!(should_run_plain_shell_for_io(false, false, true, false));
        assert!(should_run_plain_shell_for_io(false, true, false, false));
        assert!(should_run_plain_shell_for_io(false, true, true, true));
        assert!(!should_run_plain_shell_for_io(false, true, true, false));
    }

    #[test]
    fn terminal_event_dispatch_updates_app_for_interactive_events() {
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(apply_terminal_event(
            &mut app,
            Event::Paste("abc".to_string())
        ));
        assert_eq!(app.input, "abc");

        assert!(apply_terminal_event(
            &mut app,
            Event::Key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE))
        ));
        assert_eq!(app.input, "abcd");

        assert!(apply_terminal_event(&mut app, Event::Resize(120, 40)));
        assert!(apply_terminal_event(
            &mut app,
            Event::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 0,
                row: 0,
                modifiers: KeyModifiers::NONE,
            })
        ));
        assert!(!apply_terminal_event(&mut app, Event::FocusGained));
    }

    #[test]
    fn terminal_loop_inbox_applies_forwarded_terminal_events() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Terminal(Event::Paste(
            "abc".to_string(),
        ))))
        .unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(wait_for_terminal_loop_event(&mut app, &inbox).unwrap());

        assert_eq!(app.input, "abc");
    }

    #[test]
    fn terminal_loop_wake_unblocks_without_mutating_app() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Wake)).unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(!wait_for_terminal_loop_event(&mut app, &inbox).unwrap());

        assert!(app.input.is_empty());
    }

    #[test]
    fn terminal_loop_reader_error_is_reported() {
        let (tx, rx) = mpsc::channel();
        tx.send(Err("boom".to_string())).unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        let error = wait_for_terminal_loop_event(&mut app, &inbox)
            .unwrap_err()
            .to_string();

        assert!(error.contains("terminal event reader failed: boom"));
    }
}
