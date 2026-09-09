use super::*;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    PhaseAttemptEvent, PhaseAttemptLedger, PhaseTargetSnapshot,
};

fn published_result(
    phase: WorkflowPhase,
    outcome: PhaseAttemptOutcome,
) -> (tempfile::TempDir, ShellApp) {
    let (target, mut app) = completed_scan();
    let snapshot = PhaseTargetSnapshot::capture(target.path());
    let completed = PhaseAttemptCompleted::new(phase, vec![RUN_ID.into()], snapshot, outcome);
    set_projection(
        &mut app,
        vec![PhaseAttemptEvent::PhaseAttemptCompleted(completed.clone())],
        false,
    );
    let receipt = app
        .activity_mut()
        .unwrap()
        .run_focus_receipt
        .as_mut()
        .unwrap();
    receipt.attempt_id = Some(completed.attempt_id);
    receipt.origin_phase = Some(phase);
    receipt.outcome = phase_attempt_outcome_label(outcome).to_string();
    app.set_shell_view(ShellView::PlanningPicker);
    (target, app)
}

fn present(app: &mut ShellApp) {
    let origin = app.activity().unwrap().run_focus_origin;
    app.open_completed_run_destination(origin, None);
}

fn set_projection(app: &mut ShellApp, events: Vec<PhaseAttemptEvent>, degraded: bool) {
    let snapshot = PhaseTargetSnapshot::capture(app.target().unwrap());
    let ledger = PhaseAttemptLedger::from_events(events).unwrap();
    app.engagement
        .set_phase_attempt_projection_health(Some(snapshot), ledger, degraded);
}

#[test]
fn planner_results_open_their_own_phase_for_every_terminal_outcome() {
    for phase in [
        WorkflowPhase::Map,
        WorkflowPhase::Scan,
        WorkflowPhase::Review,
        WorkflowPhase::Prove,
        WorkflowPhase::Fix,
    ] {
        for outcome in [
            PhaseAttemptOutcome::Completed,
            PhaseAttemptOutcome::Partial,
            PhaseAttemptOutcome::Blocked,
            PhaseAttemptOutcome::Failed,
            PhaseAttemptOutcome::Canceled,
        ] {
            let (_target, mut app) = published_result(phase, outcome);
            present(&mut app);
            assert_eq!(
                app.shell_view(),
                ShellView::Workbench,
                "{phase:?} {outcome:?}"
            );
            assert_eq!(
                crate::ui_view_models::active_workbench_page(&app),
                WorkbenchPage::from_phase(phase)
            );
            let record = app.engagement.unresolved_phase_attempt(phase).unwrap();
            assert_eq!(record.completed.outcome, outcome);
            assert!(app.engagement.selected_phase_attempt(phase).is_none());
        }
    }
}

#[test]
fn planner_completion_preserves_background_manual_and_navigated_focus() {
    for mode in ["background", "manual", "navigated", "missing-origin"] {
        let (_target, mut app) = completed_scan();
        let expected = change_focus(&mut app, mode);
        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(app.shell_view(), expected);
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Scan)
            .is_some());
        assert!(app
            .engagement
            .selected_phase_attempt(WorkflowPhase::Scan)
            .is_none());
    }
}

fn change_focus(app: &mut ShellApp, mode: &str) -> ShellView {
    match mode {
        "background" => app.activity_mut().unwrap().run_focus_backgrounded = true,
        "manual" => {
            app.activity_mut()
                .unwrap()
                .run_focus_origin
                .as_mut()
                .unwrap()
                .auto_return = false
        }
        "navigated" => app.set_shell_view(ShellView::Report),
        _ => app.activity_mut().unwrap().run_focus_origin = None,
    }
    app.shell_view()
}

#[test]
fn planner_result_requires_matching_receipt_identity_and_outcome() {
    for changed_field in ["attempt", "phase", "outcome"] {
        let (_target, mut app) =
            published_result(WorkflowPhase::Scan, PhaseAttemptOutcome::Completed);
        let receipt = app
            .activity_mut()
            .unwrap()
            .run_focus_receipt
            .as_mut()
            .unwrap();
        match changed_field {
            "attempt" => receipt.attempt_id = Some("other-attempt".into()),
            "phase" => receipt.origin_phase = Some(WorkflowPhase::Review),
            _ => receipt.outcome = "failed".into(),
        }
        present(&mut app);
        assert_eq!(
            app.shell_view(),
            ShellView::PlanningPicker,
            "{changed_field}"
        );
    }
}

#[test]
fn planner_completion_without_a_published_receipt_restores_the_planner() {
    let (_target, mut app) = completed_scan();
    app.activity_mut().unwrap().run_focus_receipt = None;
    assert!(app.finalize_run_focus_if_idle());
    assert_eq!(app.shell_view(), ShellView::PlanningPicker);
}

#[test]
fn planner_result_requires_current_unresolved_healthy_projection() {
    for state in ["resolved", "target-switched", "degraded", "newer-attempt"] {
        let (_target, mut app) =
            published_result(WorkflowPhase::Scan, PhaseAttemptOutcome::Completed);
        let other = tempfile::tempdir().unwrap();
        change_projection(&mut app, state, other.path());
        app.set_shell_view(ShellView::PlanningPicker);
        present(&mut app);
        assert_eq!(app.shell_view(), ShellView::PlanningPicker, "{state}");
    }
}

fn change_projection(app: &mut ShellApp, state: &str, other: &std::path::Path) {
    let completed = app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Scan)
        .unwrap()
        .completed
        .clone();
    let mut events = vec![PhaseAttemptEvent::PhaseAttemptCompleted(completed.clone())];
    match state {
        "resolved" => events.push(PhaseAttemptEvent::PhaseAttemptDispositionRecorded(
            PhaseAttemptDispositionRecorded::new(
                completed.attempt_id,
                PhaseAttemptDisposition::Discarded,
            ),
        )),
        "newer-attempt" => events.push(PhaseAttemptEvent::PhaseAttemptCompleted(
            completed.with_attempt_id("newer-attempt"),
        )),
        "target-switched" => app.set_target(Some(other.to_path_buf())),
        _ => {}
    }
    set_projection(app, events, state == "degraded");
}

#[test]
fn planner_result_preserves_prompt_typing_ownership() {
    let (_target, mut app) = completed_scan();
    app.activity_mut()
        .unwrap()
        .run_focus_origin
        .as_mut()
        .unwrap()
        .input_mode = InputMode::Prompt;
    app.set_input("draft ");
    assert!(app.finalize_run_focus_if_idle());
    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('u'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert_eq!(app.input(), "draft u");
    assert_scan_pending(&app);
}
