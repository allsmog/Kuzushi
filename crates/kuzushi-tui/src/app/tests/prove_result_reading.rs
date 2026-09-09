use super::*;
use crate::ui_view_models::PhaseSurfaceId;
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseTargetSnapshot,
};

fn append_failed_prove(target: &std::path::Path, run: &str) {
    append_phase_attempt_completed(
        target,
        PhaseAttemptCompleted::new(
            WorkflowPhase::Prove,
            vec![run.into()],
            PhaseTargetSnapshot::capture(target),
            PhaseAttemptOutcome::Failed,
        ),
    )
    .unwrap();
}

#[test]
fn phase_result_projection_keeps_reading_position_only_for_the_same_attempt() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    append_failed_prove(target.path(), "first-proof-run");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.router
        .workbench_mut()
        .scroll_mut()
        .set(PhaseSurfaceId::ProveResult, 20);

    app.refresh_phase_attempt_projection();
    assert_eq!(
        app.router
            .workbench()
            .scroll()
            .get(PhaseSurfaceId::ProveResult),
        20
    );
    append_failed_prove(target.path(), "second-proof-run");
    app.refresh_phase_attempt_projection();
    assert_eq!(
        app.router
            .workbench()
            .scroll()
            .get(PhaseSurfaceId::ProveResult),
        0
    );
}

#[test]
fn narrow_pending_prove_result_routes_paging_to_its_reading_surface() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    append_failed_prove(target.path(), "proof-reading-run");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    open_workbench_page_for_test(&mut app, WorkbenchPage::Prove);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_viewport(TerminalViewport::new(40, 12));

    let update = app.reduce_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
    assert!(update.handled);
    assert!(
        app.router
            .workbench()
            .scroll()
            .get(PhaseSurfaceId::ProveResult)
            > 0
    );
    assert_eq!(
        app.router
            .workbench()
            .scroll()
            .get(PhaseSurfaceId::ProveStatus),
        0
    );
    assert!(app.input().is_empty());
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Prove)
        .is_some());
}
