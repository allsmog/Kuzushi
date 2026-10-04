use super::*;

#[test]
fn review_to_report_and_escape_preserve_the_complete_reading_state() {
    for cycle in [KeyCode::BackTab, KeyCode::Tab] {
        let (_target, mut app) = app_with_findings_and_full_phase_access(2);
        let surface = PhaseSurfaceId::ReviewDetail;
        app.router.workbench_mut().set_focus(surface);
        app.router.workbench_mut().toggle_zoom(surface);
        app.router.workbench_mut().scroll_mut().set(surface, 17);
        app.set_input_mode(InputMode::Prompt);
        app.set_input("review this\nmultiline draft");
        app.set_cursor(4);
        let before = app.router.workbench().clone();

        press_key(&mut app, KeyEvent::new(cycle, KeyModifiers::SHIFT));
        assert_eq!(app.shell_view(), ShellView::Report);
        assert!(!app.has_running_work());
        press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert_eq!(app.router.workbench(), &before);
        assert_eq!(app.input_mode(), InputMode::Prompt);
        assert_eq!(app.input(), "review this\nmultiline draft");
        assert_eq!(app.cursor(), 4);
    }
}

#[test]
fn report_shortcut_is_navigation_only_and_replaces_legacy_page_keys() {
    let (_target, mut app) = app_with_findings_and_full_phase_access(2);
    app.set_input_mode(InputMode::Prompt);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
    );
    assert_eq!(app.input(), "r");
    assert_eq!(app.shell_view(), ShellView::Workbench);
    app.set_input("");
    app.set_input_mode(InputMode::Navigate);
    let bindings = app.view_keybindings();
    assert!(bindings
        .iter()
        .any(|binding| binding.action == ViewHotkeyAction::WorkbenchReport));
    for page in [WorkbenchPage::Prove, WorkbenchPage::Fix] {
        assert!(!bindings
            .iter()
            .any(|binding| binding.action == ViewHotkeyAction::WorkbenchPage(page)));
    }
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
    );
    assert_eq!(app.shell_view(), ShellView::Report);
}

#[test]
fn completing_review_goes_to_report_without_a_proof_or_patch_queue() {
    let (_target, mut app) = app_with_findings_and_full_phase_access(2);
    app.engagement.set_phase(WorkflowPhase::Review);
    assert!(app.advance_to_next_phase().is_empty());
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.engagement.current_phase(), None);
    assert!(!app.has_running_work());
}

#[test]
fn compatibility_attempts_do_not_redirect_the_guided_destination() {
    let (target, mut app) = app_with_findings_and_full_phase_access(2);
    for phase in [WorkflowPhase::Prove, WorkflowPhase::Fix] {
        crate::test_support::record_indexed_run(
            target.path(),
            phase.word(),
            "context:build",
            serde_json::json!({"ok": false, "status": "failed", "data": {}}),
        );
        crate::test_support::append_typed_attempt(
            target.path(),
            phase,
            phase.word(),
            kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Failed,
        );
    }
    app.refresh_phase_attempt_projection();
    let journey = crate::ui_view_models::journey_model(&app).unwrap();
    assert_eq!(
        journey.destination,
        crate::ui_view_models::JourneyDestination::Report(
            crate::ui_view_models::ReportReason::ReviewComplete
        )
    );
    assert_eq!(
        journey
            .phases
            .iter()
            .map(|status| status.phase)
            .collect::<Vec<_>>(),
        WorkflowPhase::INVESTIGATION_ORDER
    );
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Prove)
        .is_some());
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Fix)
        .is_some());
}

#[test]
fn review_planner_arrow_opens_report_and_escape_restores_the_picker() {
    let (_target, mut app) = app_with_findings_and_full_phase_access(2);
    app.open_phase_picker(WorkflowPhase::Review);
    press_key(&mut app, KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Review));
    press_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Review));
    assert!(!app.has_running_work());
}

#[test]
fn completing_review_does_not_offer_retries_of_legacy_work() {
    let (_target, mut app) = app_with_findings_and_full_phase_access(2);
    app.engagement.record_failed_task(FailedPlanningTask {
        task: PlanningTaskId::VerifyFindings,
        error: "retained compatibility failure".into(),
        blocked: Vec::new(),
    });
    app.engagement.set_phase(WorkflowPhase::Review);
    assert!(app.advance_to_next_phase().is_empty());
    assert_eq!(app.shell_view(), ShellView::Report);
    assert!(app.advisory().pending_retry.is_none());
    assert_eq!(app.engagement.failed_tasks().len(), 1);
}

#[test]
fn completing_review_keeps_supported_failures_in_the_retry_gate() {
    let (_target, mut app) = app_with_findings_and_full_phase_access(2);
    for task in [PlanningTaskId::VerifyFindings, PlanningTaskId::ScanSecrets] {
        app.engagement.record_failed_task(FailedPlanningTask {
            task,
            error: "retained failure".into(),
            blocked: Vec::new(),
        });
    }
    app.engagement.set_phase(WorkflowPhase::Review);
    assert!(app.advance_to_next_phase().is_empty());
    let pending = app.advisory().pending_retry.as_ref().expect("retry gate");
    assert_eq!(pending.tasks.len(), 1);
    assert_eq!(pending.tasks[0].task, PlanningTaskId::ScanSecrets);
    assert_eq!(app.engagement.failed_tasks().len(), 2);
    assert!(!app.has_running_work());
}
