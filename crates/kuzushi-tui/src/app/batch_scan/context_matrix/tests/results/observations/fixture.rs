use super::*;
use crate::app::WorkflowPhase;

pub(super) fn review_fixture() -> (tempfile::TempDir, ShellApp, ViewHydrationKey) {
    let (root, mut app) = result_fixture();
    let target = app.target_owned().unwrap();
    crate::test_support::record_indexed_run(
        &target,
        "unrelated-scan",
        "sast:scan",
        json!({"ok":true}),
    );
    let attempt = crate::test_support::append_typed_attempt(
        &target,
        WorkflowPhase::Scan,
        "unrelated-scan",
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(&target, &attempt);
    app.refresh_phase_attempt_projection();
    let (_store, id) = recorded_pair(&target);
    let mut report = report();
    report.cases[0].occurrence.rows[0].representative_observation_ref =
        Some(format!("generation:{id}"));
    seed_current_report(&app, report);
    let expected = app.investigation_allowance_key().unwrap();
    key(&mut app, KeyCode::Char('f'));
    key(&mut app, KeyCode::Enter);
    assert!(app.router.campaign().batch_scan_config.is_none());
    (root, app, expected)
}
