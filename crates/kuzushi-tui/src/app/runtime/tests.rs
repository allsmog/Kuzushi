#[cfg(test)]
mod tests {
    use super::super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };

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
}
