use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct ControlledExporter {
    started: (Mutex<bool>, Condvar),
    released: (Mutex<bool>, Condvar),
    panic: bool,
}

impl ControlledExporter {
    fn wait_started(&self) {
        let (started, _) = self
            .started
            .1
            .wait_timeout_while(
                self.started.0.lock().unwrap(),
                Duration::from_secs(5),
                |started| !*started,
            )
            .unwrap();
        assert!(*started);
    }

    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}

impl ReportExporter for ControlledExporter {
    fn export(&self, request: &ExportRequest) -> ReportReceipt {
        *self.started.0.lock().unwrap() = true;
        self.started.1.notify_all();
        let (released, _) = self
            .released
            .1
            .wait_timeout_while(
                self.released.0.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap();
        assert!(*released, "test did not release the exporter");
        assert!(!self.panic, "owned exporter panic");
        FilesystemExporter.export(request)
    }
}

fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.rs"), "owned source\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned-report", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding(
            "owned-report",
            &kuzushi_core::Finding::new_semgrep(
                "owned.rule",
                "app.rs",
                1,
                None,
                kuzushi_core::Severity::Low,
                "Labeled report observation",
            ),
        )
        .unwrap();
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.set_input_mode(InputMode::Prompt);
    app.open_report_from_current_origin();
    app.router.report_mut().toggle_scope();
    let watermark = app.findings_read_watermark();
    let summary =
        kuzushi_core::workspace::load_workspace_review_summary(&workspace, watermark).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: app.target_owned().unwrap(),
            key: ViewHydrationKey::WorkspaceReportReview {
                findings_watermark: watermark,
            },
            value: ViewHydrationValue::WorkspaceReportReview(Ok(summary)),
        });
    let (_, wake) = TerminalLoopInbox::channel_for_test();
    app.set_loop_wake(Some(wake));
    (root, app)
}

fn request(app: &ShellApp) -> ReportExport {
    let route = app.router.report();
    ReportExport {
        campaign_id: None,
        format: route.format(),
        completeness: route.completeness(),
        output: route.path_draft().into(),
        target: app.target_owned(),
    }
}

fn start(app: &mut ShellApp, panic: bool) -> Arc<ControlledExporter> {
    let exporter = Arc::new(ControlledExporter {
        panic,
        ..Default::default()
    });
    app.runtime_state.report_export.exporter = exporter.clone();
    app.export_report_effect(request(app));
    exporter.wait_started();
    assert!(app.report_export_pending());
    exporter
}

fn settle(app: &mut ShellApp, exporter: &ControlledExporter) {
    exporter.release();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.report_export_pending() && Instant::now() < deadline {
        app.apply_report_export_result();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!app.report_export_pending());
}

fn frame(app: &ShellApp, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|row| {
            (0..width)
                .map(|column| buffer[(column, row)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn blocked_export_keeps_progress_controls_and_reading_available_at_six_sizes() {
    let (_root, mut app) = fixture();
    let exporter = start(&mut app, false);
    app.set_input("retained export draft λ");
    app.set_cursor(5);
    for (width, height) in [(40, 11), (60, 19), (80, 23), (96, 88), (120, 35), (160, 47)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let screen = frame(&app, width, height);
        assert!(screen.contains("EXPORTING"), "{width}x{height}: {screen}");
        assert!(
            screen.contains("Enter wait") || screen.contains("Enter export running"),
            "{screen}"
        );
        let update = app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert!(update.handled && update.effects.is_empty());
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("EXPORTING") && !plain.contains('\u{1b}'));
    let offset = app.router.default_scroll().offset();
    settle(&mut app, &exporter);
    assert_eq!(app.router.default_scroll().offset(), offset);
    assert_eq!((app.input(), app.cursor()), ("retained export draft λ", 5));
    assert_eq!(app.router.report().receipt().unwrap().count, Some(1));
}

#[test]
fn duplicate_export_and_quit_wait_without_starting_more_work() {
    let (root, mut app) = fixture();
    let exporter = start(&mut app, false);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("not queued"));
    app.export_report_effect(request(&app));
    app.finish_shell_quit_effect();
    assert!(!app.should_quit() && !app.has_running_work());
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("before exiting"));
    settle(&mut app, &exporter);
    assert_eq!(
        std::fs::read_to_string(root.path().join("app.rs")).unwrap(),
        "owned source\n"
    );
    app.finish_shell_quit_effect();
    assert!(app.should_quit());
}

#[test]
fn background_completion_preserves_view_prompt_cursor_and_scroll() {
    let (_root, mut app) = fixture();
    let exporter = start(&mut app, false);
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    app.set_input("draft λ");
    app.set_cursor(5);
    app.router.default_scroll_mut().set(9);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    assert!(update.handled && update.effects.is_empty());
    assert_eq!(app.input(), "draftx λ");
    let update = app.reduce_paste("\nsecond λ");
    assert!(update.handled && update.effects.is_empty());
    let expanded = app.editor().expanded_input();
    assert!(expanded.contains("draftx") && expanded.contains("second λ"));
    assert!(frame(&app, 80, 23).contains("draftx"));
    let draft = app.input().to_string();
    let cursor = app.cursor();
    settle(&mut app, &exporter);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!((app.input(), app.cursor()), (draft.as_str(), cursor));
    assert_eq!(app.editor().expanded_input(), expanded);
    assert_eq!(app.router.default_scroll().offset(), 9);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .starts_with("Exported"));
}

#[test]
fn changing_format_or_editing_path_cannot_receive_the_old_receipt() {
    for edit_path in [false, true] {
        let (_root, mut app) = fixture();
        let exporter = start(&mut app, false);
        if edit_path {
            app.router.report_mut().set_editing_path(true);
            app.router.report_mut().insert_path_text("-draft");
        } else {
            app.router.report_mut().move_format(1);
        }
        settle(&mut app, &exporter);
        assert!(app.router.report().receipt().is_none());
        assert_eq!(app.router.report().editing_path(), edit_path);
        assert!(app
            .advisory()
            .notice
            .as_ref()
            .unwrap()
            .message
            .contains("sarif"));
    }
}

#[test]
fn switching_target_does_not_attach_a_receipt_to_the_new_repository() {
    let (_root, mut app) = fixture();
    let exporter = start(&mut app, false);
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    app.set_shell_view(ShellView::Setup);
    settle(&mut app, &exporter);
    assert_eq!(app.shell_view(), ShellView::Setup);
    assert!(app.router.report().receipt().is_none());
    assert!(!other.path().join(".kuzushi/reports/report.sarif").exists());
}

#[test]
fn panicked_worker_reports_uncertain_output_and_allows_an_explicit_retry() {
    let (_root, mut app) = fixture();
    let exporter = start(&mut app, true);
    settle(&mut app, &exporter);
    assert!(app
        .router
        .report()
        .receipt()
        .unwrap()
        .error
        .as_deref()
        .unwrap()
        .contains("Inspect the destination"));
    let exporter = start(&mut app, false);
    assert!(app.router.report().receipt().is_none());
    assert!(app.advisory().notice.is_none());
    settle(&mut app, &exporter);
    assert_eq!(app.router.report().receipt().unwrap().count, Some(1));
}

#[test]
fn a_cache_refresh_cannot_discard_the_accepted_export_receipt() {
    let (_root, mut app) = fixture();
    let exporter = start(&mut app, false);
    let target = app.target_owned().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_investigation_report(&target);
    assert!(crate::ui_view_models::report_export_campaign(&app).is_err());
    assert!(app.report_export_destination().is_some());
    settle(&mut app, &exporter);
    assert_eq!(app.router.report().receipt().unwrap().count, Some(1));
}

#[test]
fn changing_report_scope_retires_the_pending_selection_even_when_switched_back() {
    let (_root, mut app) = fixture();
    let exporter = start(&mut app, false);
    app.router.report_mut().toggle_scope();
    app.router.report_mut().toggle_scope();
    settle(&mut app, &exporter);
    assert!(app.router.report().receipt().is_none());
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .starts_with("Exported"));
}
