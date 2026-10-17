use super::*;

#[test]
fn later_auxiliary_planning_cannot_replace_a_blocked_scan_in_report() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut blocked = summary("blocked-scan", "agentic-sast:scan", 10);
    blocked.status = "blocked".into();
    write_run_summary(target.path(), &blocked).unwrap();
    write_run_summary(target.path(), &summary("local-plan", "full-mode:hunt", 20)).unwrap();

    let mut app = hydrated_app(&workspace);
    app.router.report_mut().toggle_scope();
    let attempt = scan_phase_model(&app).attempt.unwrap();
    assert_eq!(attempt.run_id, "blocked-scan");
    assert_eq!(attempt.outcome, "blocked");
    let report = crate::ui_view_models::report_investigation_lines(&app).join("\n");
    assert!(report.contains("Displayed Scan: blocked"), "{report}");
    assert!(!report.contains("Displayed Scan: completed"), "{report}");
}

#[test]
fn auxiliary_legacy_scan_kind_alone_never_establishes_a_scan_projection() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    write_run_summary(target.path(), &summary("local-plan", "full-mode:hunt", 20)).unwrap();
    assert!(scan_phase_model(&hydrated_app(&workspace))
        .attempt
        .is_none());
}

#[test]
fn explicit_attempt_engines_keep_their_recorded_auxiliary_outcomes() {
    let engine = summary("child-engine", "codeql:scan", 20);
    let outcomes =
        super::super::summaries::scanner_outcomes(&[&engine], PhaseAttemptOutcome::Completed);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].run_ref.as_deref(), Some("child-engine"));
    assert_eq!(outcomes[0].outcome, "complete");
}

fn summary(run: &str, tool: &str, time: u64) -> RunSummary {
    let mut summary = RunSummary::running(run, "scan", Some(tool.into()), ".").complete();
    summary.started_at_unix = time;
    summary.completed_at_unix = Some(time + 1);
    summary
}
