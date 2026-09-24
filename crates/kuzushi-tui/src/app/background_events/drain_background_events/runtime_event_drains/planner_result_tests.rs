use super::*;
use kuzushi_core::workflow_attempts::{PhaseAttemptOutcome, PhaseResultAction};

const RUN_ID: &str = "planner-scan-result";

fn completed_scan() -> (tempfile::TempDir, ShellApp) {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().canonicalize().unwrap();
    std::fs::write(target.join("lib.rs"), "pub fn example() {}\n").unwrap();
    crate::test_support::record_indexed_run(
        &target,
        RUN_ID,
        "semgrep:scan",
        serde_json::json!({"ok": true, "status": "completed", "data": {"count": 0}}),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target));
    app.set_shell_view(ShellView::PlanningPicker);
    app.set_input_mode(InputMode::Navigate);
    let session = ActivitySession::for_phase(RUN_ID, WorkflowPhase::Scan)
        .with_phase_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new());
    let mut session = app.capture_run_focus_origin(session);
    session.mark_run_focus_terminal_pending("completed");
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    (dir, app)
}

fn assert_scan_pending(app: &ShellApp) {
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(
        crate::ui_view_models::active_workbench_page(app),
        WorkbenchPage::Scan
    );
    let attempt = app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Scan)
        .expect("Scan result remains unresolved");
    let receipt = app.activity().unwrap().run_focus_receipt.as_ref().unwrap();
    assert_eq!(
        receipt.attempt_id.as_deref(),
        Some(attempt.completed.attempt_id.as_str())
    );
    assert!(app
        .engagement
        .selected_phase_attempt(WorkflowPhase::Scan)
        .is_none());
    assert!(app.running_tool_name_owned().is_none());
}

#[test]
fn completed_planner_scan_opens_its_pending_result_without_running_again() {
    let (_target, mut app) = completed_scan();
    app.set_input("retained shell draft");
    assert!(app.finalize_run_focus_if_idle());
    assert_scan_pending(&app);
    assert_eq!(app.input_mode(), InputMode::Navigate);
    assert_eq!(app.input(), "retained shell draft");
}

#[test]
fn completed_planner_scan_keeps_result_decision_above_deferred_visualization() {
    let (_target, mut app) = completed_scan();
    app.activity_mut().unwrap().run_focus_pending_viz = Some(crate::scene3d::VizPage::Heatmap);
    assert!(app.finalize_run_focus_if_idle());
    assert_scan_pending(&app);
}

#[test]
fn completed_planner_scan_renders_use_scan_at_ordinary_sizes() {
    for (width, height) in [(80, 24), (120, 36)] {
        let (_target, mut app) = completed_scan();
        assert!(app.finalize_run_focus_if_idle());
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Use scan"), "{text}");
        assert!(!text.contains("new steps"), "{text}");
        let card = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Scan)
            .header
            .result_card
            .unwrap();
        assert!(card.actions.contains(&PhaseResultAction::Select));
        assert_scan_pending(&app);
    }
}

mod guards;
