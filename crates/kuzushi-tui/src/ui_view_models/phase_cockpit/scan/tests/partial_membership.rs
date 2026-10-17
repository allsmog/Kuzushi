use super::*;

#[test]
fn canceled_parent_without_stage_keeps_distinct_child_findings_in_partial_scan() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    prepare_partial_attempt(&workspace);
    let app = hydrated_partial_app(&workspace);
    let banner = app.phase_result_presentation(WorkflowPhase::Scan).unwrap();
    assert_eq!(
        banner.compact_summary.findings_label(),
        "findings 2 distinct"
    );
    let attempt = scan_phase_model(&app).attempt.unwrap();
    assert_eq!(attempt.outcome, "partial");
    assert_eq!(attempt.findings, Some(2));
    assert_eq!(attempt.findings_observed, Some(3));
    assert_eq!(attempt.run_refs, parent_runs());
    assert_eq!(
        attempt.severity_counts,
        [("high".into(), 1), ("medium".into(), 1)]
    );
}

#[test]
fn damaged_child_membership_does_not_claim_a_partial_ledger_count() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    prepare_partial_attempt(&workspace);
    std::fs::write(
        kuzushi_core::run_artifacts::run_dir(target.path(), "parent-2").join("result.json"),
        "damaged",
    )
    .unwrap();
    let app = hydrated_partial_app(&workspace);
    let attempt = scan_phase_model(&app).attempt.unwrap();
    assert_eq!(
        attempt.findings,
        Some(3),
        "recorded total remains available"
    );
    assert_eq!(attempt.findings_observed, None);
    assert!(attempt.severity_counts.is_empty());
}

fn prepare_partial_attempt(workspace: &WorkspaceTarget) {
    drop(super::repeated::repeated_app(workspace));
    for (run, findings) in [("parent-1", 2), ("parent-2", 1)] {
        let summary = kuzushi_core::load_run_summary(workspace.root(), run)
            .unwrap()
            .with_findings(Some(findings));
        write_run_summary(workspace.root(), &summary).unwrap();
    }
    crate::test_support::record_indexed_run(
        workspace.root(),
        "canceled-parent",
        "sast:scan",
        serde_json::json!({"ok":false,"status":"canceled","summary":"owned canceled attempt"}),
    );
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        parent_runs(),
        PhaseTargetSnapshot::capture(workspace.root()),
        PhaseAttemptOutcome::Partial,
    );
    append_phase_attempt_completed(workspace.root(), completed).unwrap();
}

fn hydrated_partial_app(workspace: &WorkspaceTarget) -> ShellApp {
    let mut app = hydrated_app(workspace);
    app.refresh_phase_attempt_projection();
    app.hydrate_view_keys_blocking(
        workspace.root(),
        parent_runs()
            .into_iter()
            .map(|run_id| ViewHydrationKey::ScanStageReceipt { run_id })
            .collect(),
    );
    let mut findings = ledger_findings("engine-1", 1, 0);
    findings.extend(ledger_findings("engine-2", 0, 1));
    let mut unrelated = ledger_findings("engine-3", 1, 0).remove(0);
    unrelated.fingerprint = "unrelated-history".into();
    findings.push(unrelated);
    app.set_findings(findings);
    app
}

fn parent_runs() -> Vec<String> {
    ["parent-1", "canceled-parent", "parent-2"]
        .map(String::from)
        .into()
}
