use super::*;
use crate::app::guided_scan::{GuidedScanFlow, GuidedScanStage};
use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

#[test]
fn completed_study_reader_shortcut_keeps_the_pending_result_and_draft() {
    let (root, mut app) = fixture();
    crate::test_support::record_indexed_run(root.path(), "scan", "sast:scan", json!({"ok":true}));
    let attempt = crate::test_support::append_typed_attempt(
        root.path(),
        WorkflowPhase::Scan,
        "scan",
        PhaseAttemptOutcome::Completed,
    );
    app.refresh_phase_attempt_projection();
    hydrate_allowance(&mut app, root.path());
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::AwaitingResult {
            phase: WorkflowPhase::Scan,
            attempt_id: attempt.attempt_id.clone(),
        }));
    app.set_input("Held draft λ\nnext line");
    app.set_input_mode(InputMode::Prompt);
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert!(app.input().ends_with('c'));
    app.set_input("Held draft λ\nnext line");
    app.set_cursor(4);
    app.set_input_mode(InputMode::Navigate);
    let route = app.router.workbench().clone();
    let before = std::fs::read(
        root.path()
            .join(".kuzushi/v3/workflow/phase-attempts.v2.jsonl"),
    )
    .unwrap();
    assert!(app.phase_result_is_open());
    assert!(
        app.scan_study_progress_key().is_some(),
        "page {:?}, allowance key {:?}",
        crate::ui_view_models::active_workbench_page(&app),
        app.investigation_allowance_key()
    );
    assert_eq!(app.scan_study_jobs_key(), 'c');
    let footer = crate::ui_view_models::footer_keybindings(&app);
    assert!(
        footer
            .iter()
            .any(|binding| binding.key == "c" && binding.label == "study jobs"),
        "{footer:?}"
    );
    app.reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Campaign);
    assert_eq!(
        app.router
            .campaign()
            .selected_campaign()
            .unwrap()
            .campaign_id,
        ID
    );
    app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench(), &route);
    assert_eq!(
        (app.input(), app.cursor(), app.input_mode()),
        ("Held draft λ\nnext line", 4, InputMode::Navigate)
    );
    assert!(app.phase_result_is_open());
    assert_eq!(
        std::fs::read(
            root.path()
                .join(".kuzushi/v3/workflow/phase-attempts.v2.jsonl")
        )
        .unwrap(),
        before
    );
}

fn hydrate_allowance(app: &mut ShellApp, root: &std::path::Path) {
    let workspace = WorkspaceTarget::new(root).unwrap();
    let allowance = kuzushi_core::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        ID,
    )
    .unwrap()
    .unwrap()
    .current_investigation;
    let target = app.target_owned().unwrap();
    let key = app.investigation_allowance_key().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key,
            value: ViewHydrationValue::InvestigationAllowance(Ok(Some(Arc::new(allowance)))),
        });
}

#[test]
fn opening_study_reveals_the_selected_job_after_sync_and_background_reads() {
    for (background, cached_catalog) in [(false, false), (true, false), (true, true)] {
        for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            let (_root, mut app) = fixture();
            if cached_catalog {
                app.open_campaign_view(None);
                assert!(!app.router.campaign().detail);
                app.set_shell_view(ShellView::Workbench);
            }
            app.set_viewport(crate::TerminalViewport::new(width, height));
            app.set_input("Held study draft λ");
            app.set_cursor(4);
            app.set_input_mode(InputMode::Navigate);
            enable_history_read(&mut app, background);
            app.open_current_scan_study();
            finish_history(&mut app);
            let job = app.router.campaign().selected_job().unwrap();
            let label = job.display_label.as_deref().unwrap_or(&job.job_id);
            let screen = drawn_screen(&app);
            assert!(
                screen.contains(label),
                "{width}x{height}, async={background}: {screen}"
            );
            assert!(screen.contains("Esc Scan"), "{width}x{height}: {screen}");
            app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
            assert_eq!(app.shell_view(), ShellView::Workbench);
            assert_eq!((app.input(), app.cursor()), ("Held study draft λ", 4));
        }
    }
}

#[test]
fn background_job_reveal_preserves_existing_reading_and_composer_ownership() {
    for mode in [InputMode::Prompt, InputMode::Navigate] {
        let (_root, mut app) = fixture();
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        app.open_campaign_view(Some(ID.into()));
        app.set_shell_view(ShellView::Workbench);
        app.set_input_mode(InputMode::Navigate);
        enable_history_read(&mut app, true);
        app.open_current_scan_study();
        app.set_input_mode(mode);
        app.set_input("Reading while history loads");
        app.router.campaign_mut().read_scroll = 7;
        finish_history(&mut app);
        assert_eq!(app.input_mode(), mode);
        assert_eq!(app.input(), "Reading while history loads");
        assert_eq!(app.router.campaign().read_scroll, 7);
    }
}

fn enable_history_read(app: &mut ShellApp, background: bool) {
    if background {
        let (_, wake) = crate::app::runtime::TerminalLoopInbox::channel_for_test();
        app.set_loop_wake(Some(wake));
    }
}

fn finish_history(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.campaign_history_loading() {
        app.apply_view_hydration_results();
        assert!(
            std::time::Instant::now() < deadline,
            "History read timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn drawn_screen(app: &ShellApp) -> String {
    use ratatui::{backend::TestBackend, Terminal};
    let size = app.viewport();
    let mut terminal = Terminal::new(TestBackend::new(size.columns, size.rows)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, app))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(size.columns as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}
