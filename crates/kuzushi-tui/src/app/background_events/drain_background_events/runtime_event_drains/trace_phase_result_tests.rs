use super::*;
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed_with_v2, PhaseAttemptCompleted, PhaseAttemptOutcome,
    PhaseResultAction, PhaseTargetSnapshot,
};

fn pending_verification() -> (tempfile::TempDir, ShellApp, String) {
    let target = tempfile::tempdir().unwrap();
    let root = target.path().canonicalize().unwrap();
    std::fs::write(root.join("input.c"), "int n = 1;\n").unwrap();
    for (run_id, tool) in [
        ("verify-prior", "verify:finding"),
        ("trace-later", "trace:expand"),
    ] {
        crate::test_support::record_indexed_run(
            &root,
            run_id,
            tool,
            serde_json::json!({"ok":true,"data":{"tool":tool}}),
        );
    }
    let attempt = PhaseAttemptCompleted::new(
        WorkflowPhase::Prove,
        vec!["verify-prior".into()],
        PhaseTargetSnapshot::capture(&root),
        PhaseAttemptOutcome::Completed,
    )
    .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string());
    append_phase_attempt_completed_with_v2(&root, attempt.clone()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root));
    app.refresh_phase_attempt_projection();
    (target, app, attempt.attempt_id)
}

#[test]
fn trace_completion_keeps_pending_verification_and_has_no_proof_selection() {
    let (_target, mut app, attempt_id) = pending_verification();
    // Even a compatibility caller supplying a phase cannot create a proof result.
    let mut session = ActivitySession::for_phase("trace-later", WorkflowPhase::Prove);
    session.mark_run_focus_terminal_pending("completed");
    app.set_activity(Some(session));
    assert!(app.finalize_run_focus_if_idle());
    let pending = app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Prove)
        .unwrap();
    assert_eq!(pending.completed.attempt_id, attempt_id);
    let receipt = app.activity().unwrap().run_focus_receipt.as_ref().unwrap();
    assert_eq!(receipt.origin_phase, None);
    assert_eq!(receipt.attempt_id, None);
    assert!(!receipt.actions.contains(&PhaseResultAction::Select));
    assert!(!receipt
        .actions
        .contains(&PhaseResultAction::SelectAndContinue));
}
