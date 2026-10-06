use super::*;
use kuzushi_core::workflow_attempts::{
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    PhaseAttemptEvent, PhaseAttemptLedger, PhaseAttemptOutcome, PhaseTargetSnapshot,
};

fn snapshot(revision: &str) -> PhaseTargetSnapshot {
    PhaseTargetSnapshot {
        target: "/report-scan-attempt-target".to_string(),
        revision: Some(revision.to_string()),
        dirty: false,
    }
}

fn three_pass_attempt(revision: &str) -> PhaseAttemptCompleted {
    PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec!["trial-1".into(), "trial-2".into(), "trial-3".into()],
        snapshot(revision),
        PhaseAttemptOutcome::Completed,
    )
}

/// A ledger whose only Scan attempt was selected on revision `abc`.
fn selected_on_earlier_revision() -> (PhaseAttemptLedger, PhaseAttemptCompleted) {
    let attempt = three_pass_attempt("abc");
    let selection = PhaseAttemptDispositionRecorded::new(
        &attempt.attempt_id,
        PhaseAttemptDisposition::Selected {
            acknowledged_partial: false,
        },
    );
    let ledger = PhaseAttemptLedger::from_events([
        PhaseAttemptEvent::PhaseAttemptCompleted(attempt.clone()),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(selection),
    ])
    .unwrap();
    (ledger, attempt)
}

fn app_at(revision: &str, degraded: bool) -> ShellApp {
    let (ledger, _) = selected_on_earlier_revision();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement
        .set_phase_attempt_projection_health(Some(snapshot(revision)), ledger, degraded);
    app
}

#[test]
fn report_keeps_the_latest_selected_study_after_source_drift() {
    let app = app_at("def", false);
    let attempt = app
        .report_scan_attempt()
        .expect("earlier study stays reportable");
    assert!(!attempt.current);
    assert_eq!(attempt.run_refs, vec!["trial-1", "trial-2", "trial-3"]);
    assert_eq!(app.report_scan_run_refs(), attempt.run_refs);
}

#[test]
fn report_marks_the_selected_study_current_on_its_own_source() {
    let attempt = app_at("abc", false).report_scan_attempt().unwrap();
    assert!(attempt.current);
}

#[test]
fn degraded_ledger_never_offers_history_as_a_report_study() {
    let app = app_at("def", true);
    assert!(app.report_scan_attempt().is_none());
    assert!(app.report_scan_run_refs().is_empty());
}

#[test]
fn scan_page_shows_the_earlier_source_attempt_instead_of_a_legacy_run() {
    let app = app_at("def", false);
    let cockpit = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Scan);
    let crate::ui_view_models::PhaseCockpitBody::Scan(scan) = cockpit.body else {
        panic!("Scan cockpit body expected");
    };
    let attempt = scan.attempt.expect("selected history is projected");
    assert_eq!(attempt.disposition, "selected · earlier source");
    assert_eq!(attempt.run_refs.len(), 3);
}

fn opened_app_with_draft() -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Report);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("retained draft");
    assert!(!app
        .engagement
        .has_phase_attempt_for_target(WorkflowPhase::Scan));
    (target, app)
}

fn record_external_scan_attempt(target: &std::path::Path) {
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec!["detached-run".into()],
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    );
    kuzushi_core::workflow_attempts::append_phase_attempt_completed(target, completed).unwrap();
}

#[test]
fn external_phase_ledger_write_reloads_attempts_without_moving_focus() {
    let (target, mut app) = opened_app_with_draft();
    record_external_scan_attempt(target.path());

    app.apply_external_workspace_state_change(&[PathBuf::from(
        ".kuzushi/v3/workflow/phase-attempts.jsonl",
    )]);

    assert!(app
        .engagement
        .has_phase_attempt_for_target(WorkflowPhase::Scan));
    assert_eq!(app.shell_view(), ShellView::Report);
    assert_eq!(app.input_mode(), InputMode::Prompt);
    assert_eq!(app.input(), "retained draft");
}

#[test]
fn unrelated_state_artifacts_do_not_reload_the_phase_ledger() {
    let (target, mut app) = opened_app_with_draft();
    record_external_scan_attempt(target.path());

    app.apply_external_workspace_state_change(&[PathBuf::from(".kuzushi/v3/runs/run-1/done.json")]);

    assert!(!app
        .engagement
        .has_phase_attempt_for_target(WorkflowPhase::Scan));
}
