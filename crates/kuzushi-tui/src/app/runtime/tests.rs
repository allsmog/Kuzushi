#[cfg(test)]
mod tests {
    use super::super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use ratatui::{
        backend::{ClearType, TestBackend, WindowSize},
        buffer::Cell,
        layout::{Position, Size},
    };
    use std::sync::mpsc;

    struct CursorQueryTrackingBackend {
        inner: TestBackend,
        cursor_queries: usize,
    }

    impl Backend for CursorQueryTrackingBackend {
        type Error = std::convert::Infallible;

        fn draw<'a, I>(&mut self, content: I) -> std::result::Result<(), Self::Error>
        where
            I: Iterator<Item = (u16, u16, &'a Cell)>,
        {
            self.inner.draw(content)
        }

        fn hide_cursor(&mut self) -> std::result::Result<(), Self::Error> {
            self.inner.hide_cursor()
        }

        fn show_cursor(&mut self) -> std::result::Result<(), Self::Error> {
            self.inner.show_cursor()
        }

        fn get_cursor_position(&mut self) -> std::result::Result<Position, Self::Error> {
            self.cursor_queries += 1;
            self.inner.get_cursor_position()
        }

        fn set_cursor_position<P: Into<Position>>(
            &mut self,
            position: P,
        ) -> std::result::Result<(), Self::Error> {
            self.inner.set_cursor_position(position)
        }

        fn clear(&mut self) -> std::result::Result<(), Self::Error> {
            self.inner.clear()
        }

        fn clear_region(&mut self, clear_type: ClearType) -> std::result::Result<(), Self::Error> {
            self.inner.clear_region(clear_type)
        }

        fn size(&self) -> std::result::Result<Size, Self::Error> {
            self.inner.size()
        }

        fn window_size(&mut self) -> std::result::Result<WindowSize, Self::Error> {
            self.inner.window_size()
        }

        fn flush(&mut self) -> std::result::Result<(), Self::Error> {
            self.inner.flush()
        }
    }

    #[test]
    fn plain_shell_detection_covers_forced_non_tty_and_tty_modes() {
        assert!(should_run_plain_shell_for_io(true, true, true, false));
        assert!(should_run_plain_shell_for_io(false, false, true, false));
        assert!(should_run_plain_shell_for_io(false, true, false, false));
        assert!(should_run_plain_shell_for_io(false, true, true, true));
        assert!(!should_run_plain_shell_for_io(false, true, true, false));
    }

    #[test]
    fn transcript_metadata_distinguishes_interactive_plain_and_scripted_shells() {
        assert_eq!(shell_mode_label(false, true), "interactive");
        assert_eq!(shell_mode_label(true, true), "plain");
        assert_eq!(shell_mode_label(true, false), "scripted");
    }

    #[test]
    fn full_redraw_clears_without_querying_cursor_position() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.ui_mut().request_full_redraw();
        let backend = CursorQueryTrackingBackend {
            inner: TestBackend::with_lines(["stale output"]),
            cursor_queries: 0,
        };
        let mut terminal = Terminal::new(backend).unwrap();

        assert!(clear_terminal_after_external_output(&mut terminal, &mut app).unwrap());
        assert_eq!(terminal.backend().cursor_queries, 0);
        assert!(terminal
            .backend()
            .inner
            .buffer()
            .content
            .iter()
            .all(|cell| cell.symbol() == " "));
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
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Review));
        app.router.workbench_mut().set_focus(WorkbenchPane::Details);
        let viewport = app.viewport();
        let plan = crate::renderer::workbench_phase_plan_for_app(
            &app,
            ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
        )
        .expect("workbench presentation plan");
        let queue = plan
            .surface(crate::ui_view_models::PhaseSurfaceId::ReviewQueue)
            .expect("visible review queue");
        assert!(apply_terminal_event(
            &mut app,
            Event::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: queue.rect.x + queue.rect.width / 2,
                row: queue.rect.y + queue.rect.height / 2,
                modifiers: KeyModifiers::NONE,
            })
        ));
        assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
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
        app.set_shell_view(ShellView::Catalog);

        assert!(apply_launch_start_view(&mut app));

        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(app.router.workbench().focus(), WorkbenchPane::Findings);
    }

    #[test]
    fn launch_start_view_preserves_onboarding_picker_through_command_update() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.open_model_picker();

        assert!(apply_launch_start_view(&mut app));

        assert_eq!(app.shell_view(), ShellView::Setup);
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Model));
    }

    #[test]
    fn launch_target_picker_is_applied_through_command_update() {
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(apply_launch_target_picker(&mut app));

        assert_eq!(app.shell_view(), ShellView::TargetPicker);
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
            result: serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": {"runId": "run-1", "findingsCount": 0},
            }),
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

        assert!(apply_runtime_messages_with_outcome(&mut app, now, None).changed);

        assert_eq!(app.ctrl_c_armed_at(), None);
        assert_eq!(app.scan().unwrap().stage, "running semgrep");
    }

    #[test]
    fn runtime_refresh_syncs_view_change_before_redraw() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        assert!(
            apply_runtime_messages_and_sync_view(&mut app, std::time::Instant::now(), None,)
                .changed
        );
        app.router.default_scroll_mut().set(25);
        app.set_shell_view(ShellView::Tools);

        let outcome =
            apply_runtime_messages_and_sync_view(&mut app, std::time::Instant::now(), None);

        assert!(outcome.changed);
        assert_eq!(app.router.default_scroll().offset(), 0);
        app.go_back();
        assert_eq!(app.shell_view(), ShellView::Workbench);
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
    fn terminal_loop_wake_coalesces_a_notification_burst() {
        let (inbox, wake) = TerminalLoopInbox::channel_for_test();
        for _ in 0..1_000 {
            wake.notify();
        }

        assert!(matches!(
            inbox.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
        assert!(inbox.recv_timeout(Duration::ZERO).unwrap().is_none());
    }

    #[test]
    fn exhausted_job_slice_rearms_a_consumed_wake() {
        let (inbox, wake) = TerminalLoopInbox::channel_for_test();
        wake.notify();
        assert!(matches!(
            inbox.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));

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
        ticket.send(ShellEvent::Scan(ScanEvent::Stage("first".to_string())));
        ticket.send(ShellEvent::Scan(ScanEvent::Stage("second".to_string())));

        let outcome = app.drain_job_events_for(Duration::ZERO);
        rearm_work_tail(&wake, outcome.time_slice_exhausted);

        assert_eq!(app.scan().unwrap().stage, "first");
        assert!(matches!(
            inbox.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
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
