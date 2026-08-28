#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::ui_view_models::PhaseSurfaceId;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use ratatui::{
        backend::{ClearType, TestBackend, WindowSize},
        buffer::Cell,
        layout::{Position, Size},
    };
    use std::sync::mpsc;

    fn wb_focus(app: &ShellApp) -> crate::ui_view_models::PhaseSurfaceId {
        app.router
            .workbench()
            .focus_for(crate::ui_view_models::active_workbench_page(app))
    }
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
        app.router
            .workbench_mut()
            .set_focus(PhaseSurfaceId::ReviewDetail);
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
        assert_eq!(wb_focus(&app), PhaseSurfaceId::ReviewQueue);
        assert!(!apply_terminal_event(&mut app, Event::FocusGained));
    }

    #[test]
    fn focus_events_track_state_without_dirtying_the_frame() {
        let mut app = ShellApp::new(V2Config::default(), None);
        assert_eq!(
            app.ui().terminal_focus(),
            crate::app::FocusState::Unknown,
            "focus starts unreported so notifications fail closed"
        );

        assert!(!apply_terminal_event(&mut app, Event::FocusLost));
        assert_eq!(app.ui().terminal_focus(), crate::app::FocusState::Blurred);

        assert!(!apply_terminal_event(&mut app, Event::FocusGained));
        assert_eq!(app.ui().terminal_focus(), crate::app::FocusState::Focused);
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
        assert_eq!(wb_focus(&app), PhaseSurfaceId::ReviewQueue);
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
    fn launch_start_view_keeps_a_persisted_dfd_contextual() {
        let (target, mut app) = app_with_persisted_dfd();

        assert!(apply_launch_start_view(&mut app));

        assert_eq!(app.shell_view(), ShellView::Workbench);
        drop(target);
    }

    #[test]
    fn launch_target_picker_is_applied_through_command_update() {
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(apply_launch_target_picker(&mut app));

        assert_eq!(app.shell_view(), ShellView::TargetPicker);
        assert!(!app.router.target_picker().candidates().is_empty());
    }

    fn app_with_persisted_dfd() -> (tempfile::TempDir, ShellApp) {
        let target = tempfile::tempdir().expect("temporary target");
        let document = serde_json::json!({
            "dfd": {
                "nodes": [
                    {
                        "id": "browser",
                        "name": "Browser",
                        "type": "external entity",
                        "trustZone": "internet"
                    },
                    {
                        "id": "api",
                        "name": "API",
                        "type": "process",
                        "trustZone": "application"
                    }
                ],
                "flows": [{
                    "id": "request",
                    "sourceId": "browser",
                    "targetId": "api",
                    "description": "HTTPS request"
                }]
            }
        });
        kuzushi_core::save_persistent_threat_model(target.path(), &document, true)
            .expect("persist DFD");
        let workspace = WorkspaceTarget::new(target.path()).expect("workspace target");
        let app = ShellApp::new(V2Config::default(), Some(&workspace));
        (target, app)
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

        assert!(wait_for_terminal_event_batch(&mut app, &inbox).unwrap());

        assert_eq!(app.input(), "abc");
    }

    #[test]
    fn terminal_loop_wake_unblocks_without_mutating_app() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Wake)).unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(!wait_for_terminal_event_batch(&mut app, &inbox).unwrap());

        assert!(app.input().is_empty());
    }

    #[test]
    fn terminal_event_batch_applies_a_printable_burst_in_arrival_order() {
        let (tx, rx) = mpsc::channel();
        let expected = (0..80)
            .map(|index| char::from(b'a' + (index % 26) as u8))
            .collect::<String>();
        for character in expected.chars() {
            tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Key(
                KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
            ))))
            .unwrap();
        }
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        let outcome = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(outcome.received_count, 80);
        assert_eq!(outcome.terminal_event_count, 80);
        assert!(!outcome.hit_batch_bound);
        assert_eq!(app.input(), expected);
    }

    #[test]
    fn terminal_event_batch_preserves_mixed_event_order_and_ignores_wakes() {
        let (tx, rx) = mpsc::channel();
        for event in [
            TerminalLoopEvent::Terminal(TermEvent::Paste("ab".to_string())),
            TerminalLoopEvent::Wake,
            TerminalLoopEvent::Terminal(TermEvent::Resize {
                columns: 144,
                rows: 52,
            }),
            TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent::new(
                KeyCode::Char('c'),
                KeyModifiers::NONE,
            ))),
        ] {
            tx.send(Ok(event)).unwrap();
        }
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        let outcome = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(outcome.received_count, 4);
        assert_eq!(outcome.terminal_event_count, 3);
        assert_eq!(app.input(), "abc");
        assert_eq!(app.viewport(), TerminalViewport::new(144, 52));
    }

    #[test]
    fn command_submit_non_press_does_not_confirm_the_new_planning_picker() {
        for (command, phase) in [("/map", WorkflowPhase::Map), ("/scan", WorkflowPhase::Scan)] {
            for kind in [KeyEventKind::Release, KeyEventKind::Repeat] {
                assert_command_submit_non_press_stays_in_picker(command, phase, kind);
            }
        }
    }

    fn assert_command_submit_non_press_stays_in_picker(
        command: &str,
        phase: WorkflowPhase,
        kind: KeyEventKind,
    ) {
        let target = tempfile::tempdir().expect("temp target");
        let workspace = WorkspaceTarget::new(target.path()).expect("workspace");
        let (tx, rx) = mpsc::channel();
        for event in [
            TerminalLoopEvent::Terminal(TermEvent::Paste(command.to_string())),
            TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE,
            ))),
            TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent::new_with_kind(
                KeyCode::Enter,
                KeyModifiers::NONE,
                kind,
            ))),
        ] {
            tx.send(Ok(event)).unwrap();
        }
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        let outcome = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(outcome.received_count, 3, "{command} {kind:?}");
        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert_eq!(app.engagement.current_phase(), Some(phase));
        assert!(!app.has_running_work(), "{command} {kind:?}");
    }

    #[test]
    fn terminal_event_batch_limit_leaves_the_tail_for_the_next_batch() {
        let (tx, rx) = mpsc::channel();
        for _ in 0..300 {
            tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(
                "x".to_string(),
            ))))
            .unwrap();
        }
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        let first = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();
        let second = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(first.received_count, TERMINAL_EVENT_BATCH_LIMIT);
        assert!(first.hit_batch_bound);
        assert_eq!(second.received_count, 300 - TERMINAL_EVENT_BATCH_LIMIT);
        assert!(!second.hit_batch_bound);
        assert_eq!(app.input().len(), 300);
    }

    #[test]
    fn queued_input_preempts_one_background_refresh_but_not_two() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(
            "first".to_string(),
        ))))
        .unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut state = TerminalLoopState::default();

        let first = take_queued_input_batch(&mut app, &mut state, &inbox)
            .unwrap()
            .expect("queued input bypasses background refresh");
        tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(
            "second".to_string(),
        ))))
        .unwrap();

        assert_eq!(first.terminal_event_count, 1);
        assert_eq!(app.input(), "first");
        assert!(take_queued_input_batch(&mut app, &mut state, &inbox)
            .unwrap()
            .is_none());
        assert_eq!(
            app.input(),
            "first",
            "the next loop must service background work before more queued input"
        );
    }

    #[test]
    fn queued_wake_never_spends_the_input_preemption() {
        let (tx, rx) = mpsc::channel();
        tx.send(Ok(TerminalLoopEvent::Wake)).unwrap();
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut state = TerminalLoopState::default();

        assert!(take_queued_input_batch(&mut app, &mut state, &inbox)
            .unwrap()
            .is_none());
        tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(
            "ready".to_string(),
        ))))
        .unwrap();

        assert!(take_queued_input_batch(&mut app, &mut state, &inbox)
            .unwrap()
            .is_some());
        assert_eq!(app.input(), "ready");
    }

    #[test]
    fn running_activity_transition_stops_the_current_batch() {
        let (tx, rx) = mpsc::channel();
        for event in [
            TerminalLoopEvent::Terminal(TermEvent::Paste("activity".to_string())),
            TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE,
            ))),
            TerminalLoopEvent::Terminal(TermEvent::Paste("tail".to_string())),
        ] {
            tx.send(Ok(event)).unwrap();
        }
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_running_tool_for_test("context:build");
        app.set_shell_view(ShellView::Workbench);

        let outcome = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(outcome.received_count, 2);
        assert_eq!(
            outcome.run_focus_transition_from,
            Some(ShellView::Workbench)
        );
        assert!(!outcome.hit_batch_bound);
        assert_eq!(app.shell_view(), ShellView::Activity);
        assert!(matches!(
            inbox.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Terminal(TermEvent::Paste(tail))) if tail == "tail"
        ));
    }

    #[test]
    fn quit_request_stops_before_consuming_queued_tail_input() {
        let (tx, rx) = mpsc::channel();
        for event in [
            TerminalLoopEvent::Terminal(TermEvent::Key(KeyEvent::new(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL,
            ))),
            TerminalLoopEvent::Terminal(TermEvent::Paste("tail".to_string())),
        ] {
            tx.send(Ok(event)).unwrap();
        }
        let inbox = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);

        let outcome = wait_for_terminal_event_batch_with_limits(
            &mut app,
            &inbox,
            Duration::ZERO,
            TERMINAL_EVENT_BATCH_LIMIT,
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(outcome.received_count, 1);
        assert!(!outcome.hit_batch_bound);
        assert!(app.should_quit());
        assert!(matches!(
            inbox.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Terminal(TermEvent::Paste(tail))) if tail == "tail"
        ));
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
    fn bounded_input_tail_does_not_spend_background_wake_allowance() {
        let (tx, rx) = mpsc::channel();
        for _ in 0..=TERMINAL_EVENT_BATCH_LIMIT {
            tx.send(Ok(TerminalLoopEvent::Terminal(TermEvent::Paste(
                "x".to_string(),
            ))))
            .unwrap();
        }
        let input = TerminalLoopInbox::from_receiver(rx);
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut state = TerminalLoopState::default();
        let batch = take_queued_input_batch(&mut app, &mut state, &input)
            .unwrap()
            .expect("bounded input batch");
        assert!(batch.hit_batch_bound);

        let (background, wake) = TerminalLoopInbox::channel_for_test();
        for _ in 0..2 {
            rearm_work_tail(&wake, true);
            assert!(matches!(
                background.recv_timeout(Duration::from_millis(20)).unwrap(),
                Some(TerminalLoopEvent::Wake)
            ));
        }
    }

    #[test]
    fn background_tail_rearm_does_not_wait_for_the_idle_poll() {
        let (inbox, wake) = TerminalLoopInbox::channel_for_test();
        let started = Instant::now();

        rearm_work_tail(&wake, true);
        assert!(matches!(
            inbox.recv_timeout(Duration::from_millis(20)).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
        rearm_work_tail(&wake, true);
        assert!(matches!(
            inbox.recv_timeout(Duration::from_millis(20)).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));

        assert!(started.elapsed() < Duration::from_millis(100));
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

        let error = wait_for_terminal_event_batch(&mut app, &inbox)
            .unwrap_err()
            .to_string();

        assert!(error.contains("terminal event reader failed: boom"));
    }

    /// Event floods must not monopolize the loop with imperceptible draws,
    /// while input-driven frames retain a tighter latency budget.
    #[test]
    fn redraw_priority_caps_background_work_without_throttling_input() {
        let base = std::time::Instant::now();
        let just_drawn = Some(base);
        let long_ago = Some(base - BACKGROUND_FRAME_INTERVAL * 2);

        // Draw gating: clean frames never draw; dirty frames draw when the
        // interval elapsed (or nothing was drawn yet), defer when inside it.
        assert!(!should_draw_frame(
            false,
            RedrawPriority::Background,
            None,
            base
        ));
        assert!(should_draw_frame(
            true,
            RedrawPriority::Background,
            None,
            base
        ));
        assert!(should_draw_frame(
            true,
            RedrawPriority::Background,
            long_ago,
            base
        ));
        assert!(!should_draw_frame(
            true,
            RedrawPriority::Background,
            just_drawn,
            base + INTERACTIVE_FRAME_INTERVAL
        ));
        assert!(should_draw_frame(
            true,
            RedrawPriority::Interactive,
            just_drawn,
            base + INTERACTIVE_FRAME_INTERVAL
        ));

        let idle = Duration::from_millis(250);
        assert_eq!(
            deferred_frame_timeout(idle, false, RedrawPriority::Background, just_drawn, base),
            idle
        );
        assert_eq!(
            deferred_frame_timeout(idle, true, RedrawPriority::Background, None, base),
            Duration::ZERO
        );
        assert_eq!(
            deferred_frame_timeout(idle, true, RedrawPriority::Interactive, just_drawn, base),
            INTERACTIVE_FRAME_INTERVAL
        );
        // A view cadence faster than the frame cap is never slowed down.
        let scene = Duration::from_millis(5);
        assert_eq!(
            deferred_frame_timeout(scene, true, RedrawPriority::Interactive, just_drawn, base),
            scene
        );
    }

    #[test]
    fn interactive_redraw_request_upgrades_a_pending_background_frame() {
        let mut state = TerminalLoopState::default();
        state.needs_redraw = false;

        state.request_redraw(true, RedrawPriority::Background);
        state.request_redraw(true, RedrawPriority::Interactive);
        state.request_redraw(true, RedrawPriority::Background);

        assert!(state.needs_redraw);
        assert_eq!(state.redraw_priority, RedrawPriority::Interactive);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "same-host idle CPU gate; run serially with pnpm test:performance"]
    fn workbench_warmed_idle_terminal_loop_cpu_stays_within_budget() {
        const IDLE_WINDOW: Duration = Duration::from_millis(300);
        const CPU_BUDGET: Duration = Duration::from_millis(15);
        let (inbox, keep_sender_alive) = TerminalLoopInbox::channel_for_test();
        let cpu_before = current_thread_cpu_time();
        let wall_started = Instant::now();

        assert!(inbox.recv_timeout(IDLE_WINDOW).unwrap().is_none());

        let wall = wall_started.elapsed();
        let cpu = current_thread_cpu_time().saturating_sub(cpu_before);
        drop(keep_sender_alive);
        eprintln!("idle terminal poll wall={wall:?}, thread_cpu={cpu:?}");
        assert!(
            wall >= Duration::from_millis(250),
            "poll returned early: {wall:?}"
        );
        assert!(
            cpu <= CPU_BUDGET,
            "idle terminal poll consumed {cpu:?} thread CPU in {wall:?}; budget={CPU_BUDGET:?}"
        );
    }

    #[cfg(unix)]
    fn current_thread_cpu_time() -> Duration {
        let mut stamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: `stamp` points to writable storage for one `timespec`; on a
        // successful call the OS initializes it before `assume_init`.
        let result =
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, stamp.as_mut_ptr()) };
        assert_eq!(result, 0, "read current thread CPU clock");
        // SAFETY: the successful `clock_gettime` call initialized `stamp`.
        let stamp = unsafe { stamp.assume_init() };
        Duration::new(stamp.tv_sec as u64, stamp.tv_nsec as u32)
    }

    /// The panic hook must restore the terminal exactly once (the guard is
    /// consumed on first take) and must keep unwinding so the panic message
    /// still reaches the operator. One sequential test owns the global flag
    /// so parallel test threads never race it.
    #[test]
    fn terminal_panic_guard_is_armed_once_and_consumed_by_the_hook() {
        // The guard is consumable: exactly one restore per armed session.
        mark_terminal_guard_active();
        assert!(take_terminal_guard());
        assert!(!take_terminal_guard(), "second take must be a no-op");

        // Chain under a quiet probe hook so the assertion below observes the
        // chained call instead of default-hook stderr noise.
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = observed.clone();
        std::panic::set_hook(Box::new(move |_| {
            probe.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        install_terminal_panic_hook();

        mark_terminal_guard_active();
        let unwound = std::panic::catch_unwind(|| panic!("t3 probe"));

        assert!(unwound.is_err(), "panic must keep unwinding after the hook");
        assert!(
            observed.load(std::sync::atomic::Ordering::SeqCst),
            "hook must chain to the previous hook"
        );
        assert!(
            !take_terminal_guard(),
            "hook must consume the guard so restore runs exactly once"
        );
        let _ = std::panic::take_hook();
    }
}
