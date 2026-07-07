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
        assert_eq!(app.input(), "abc");

        assert!(apply_terminal_event(
            &mut app,
            Event::Key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE))
        ));
        assert_eq!(app.input(), "abcd");

        assert!(apply_terminal_event(&mut app, Event::Resize(120, 40)));
        app.shell_view = ShellView::Workbench;
        app.router.workbench_mut().set_focus(WorkbenchPane::Details);
        assert!(apply_terminal_event(
            &mut app,
            Event::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 0,
                row: 0,
                modifiers: KeyModifiers::NONE,
            })
        ));
        assert_eq!(app.router.workbench().focus(), WorkbenchPane::Source);
        assert!(!apply_terminal_event(&mut app, Event::FocusGained));
    }

    #[test]
    fn initial_terminal_size_is_applied_through_msg_update() {
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(apply_initial_terminal_size(&mut app, 120, 0));

        assert_eq!(app.viewport(), TerminalViewport::new(120, 1));
    }

    #[test]
    fn launch_start_view_is_applied_through_command_update() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Catalog;

        assert!(apply_launch_start_view(&mut app));

        assert_eq!(app.shell_view, ShellView::Workbench);
        assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    }

    #[test]
    fn launch_start_view_preserves_onboarding_picker_through_command_update() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::ModelPicker;

        assert!(apply_launch_start_view(&mut app));

        assert_eq!(app.shell_view, ShellView::ModelPicker);
    }

    #[test]
    fn launch_target_picker_is_applied_through_command_update() {
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(apply_launch_target_picker(&mut app));

        assert_eq!(app.shell_view, ShellView::TargetPicker);
        assert!(!app.router.target_picker().candidates().is_empty());
    }

    #[test]
    fn pending_background_events_are_applied_through_runtime_helper() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let ticket = app.jobs_mut().start(JobKind::Run, "scan");
        app.set_scan_panel(Some(ScanPanelState {
            run_id: None,
            target: std::path::PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));
        ticket.send(ShellEvent::Scan(ScanEvent::Finished {
            run_id: "run-1".to_string(),
            findings_count: 0,
            cost_usd: None,
        }));

        assert!(apply_pending_background_events(&mut app));

        assert!(!app.scan().unwrap().running);
        assert!(!app.jobs().is_running(JobKind::Run));
    }

    #[test]
    fn runtime_messages_apply_tick_and_job_updates_together() {
        let now = std::time::Instant::now();
        let mut app = ShellApp::new(V2Config::default(), None);
        let ticket = app.jobs_mut().start(JobKind::Run, "scan");
        app.set_ctrl_c_armed_at(Some(
            now - CTRL_C_ARM_WINDOW - std::time::Duration::from_millis(1),
        ));
        app.set_scan_panel(Some(ScanPanelState {
            run_id: None,
            target: std::path::PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));
        ticket.send(ShellEvent::Scan(ScanEvent::Stage(
            "running semgrep".to_string(),
        )));

        assert!(apply_runtime_messages(&mut app, now));

        assert_eq!(app.ctrl_c_armed_at(), None);
        assert_eq!(app.scan().unwrap().stage, "running semgrep");
    }

    #[test]
    fn terminal_loop_inbox_applies_forwarded_terminal_events() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(
            "abc".to_string(),
        ))))
        .unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(wait_for_terminal_loop_event(&mut app, &inbox).unwrap());

        assert_eq!(app.input(), "abc");
    }

    #[test]
    fn terminal_loop_wake_unblocks_without_mutating_app() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Wake)).unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(!wait_for_terminal_loop_event(&mut app, &inbox).unwrap());

        assert!(app.input().is_empty());
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
