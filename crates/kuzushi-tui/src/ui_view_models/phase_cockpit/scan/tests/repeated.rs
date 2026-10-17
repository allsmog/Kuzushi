use super::*;
use kuzushi_core::findings::{FindingSource, Severity};

pub(super) fn repeated_app(workspace: &WorkspaceTarget) -> ShellApp {
    let target = workspace.root();
    for pass in 1..=3 {
        let parent = format!("parent-{pass}");
        record_typed_scan_attempt(target, &parent);
        let mut receipt = kuzushi_core::run_artifacts::load_scan_stage_data(target, &parent)
            .unwrap()
            .unwrap();
        receipt.run_refs = vec![format!("engine-{pass}")];
        let scan = receipt.scan.as_mut().unwrap();
        scan.engines.truncate(1);
        scan.engines[0].run_ref = Some(format!("engine-{pass}"));
        scan.finding_delta = ScanFindingDelta {
            added: u64::from(pass != 2),
            updated: u64::from(pass == 2),
        };
        crate::test_support::record_indexed_run(
            target,
            &parent,
            "sast:scan",
            serde_json::json!({"ok":true,"data":{"phaseStages":[receipt]}}),
        );
    }
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        (1..=3).map(|pass| format!("parent-{pass}")).collect(),
        PhaseTargetSnapshot::capture(target),
        PhaseAttemptOutcome::Completed,
    );
    append_phase_attempt_completed(target, completed).unwrap();
    let mut app = hydrated_app(workspace);
    app.refresh_phase_attempt_projection();
    app.hydrate_view_keys_blocking(
        target,
        (1..=3)
            .map(|pass| ViewHydrationKey::ScanStageReceipt {
                run_id: format!("parent-{pass}"),
            })
            .collect(),
    );
    app
}

#[test]
fn selected_attempt_projects_every_parent_and_engine_with_distinct_findings() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = repeated_app(&workspace);
    let mut recurring = ledger_findings("engine-2", 1, 0).remove(0);
    recurring.sources = vec![FindingSource {
        tool: "semgrep".into(),
        vuln_source: None,
        source_signature: "recurring".into(),
        first_scan_id: "engine-1".into(),
        last_scan_id: "engine-2".into(),
        first_seen_at: "2026-10-05T00:00:00Z".into(),
        last_seen_at: "2026-10-05T00:01:00Z".into(),
    }];
    let mut later = ledger_findings("engine-3", 0, 1).remove(0);
    later.severity = Severity::Medium;
    app.set_findings(vec![recurring, later]);
    let presentation = app.phase_result_presentation(WorkflowPhase::Scan).unwrap();
    assert_eq!(
        presentation.compact_summary.findings_label(),
        "findings 2 distinct"
    );
    let model = scan_phase_model(&app);
    assert!(model.plan.starts_with("3 scan runs"));
    assert_eq!(model.engine_outcomes.len(), 3);
    let attempt = model.attempt.unwrap();
    assert_eq!(attempt.outcome, "completed");
    assert_eq!(attempt.run_refs.len(), 6);
    assert_eq!(attempt.findings, Some(2));
    assert_eq!(attempt.findings_observed, Some(3));
    // The three receipts recorded a combined 2 + 1 fingerprint delta for runs
    // the ledger attributes two findings to, so that delta no longer counts
    // the findings the breakdown below describes and the panel states the
    // reconciled `distinct`/`observations` pair instead (issue #172).
    assert_eq!(
        (attempt.findings_added, attempt.findings_updated),
        (None, None)
    );
    assert_eq!(
        attempt.severity_counts,
        [("high".into(), 1), ("medium".into(), 1)]
    );
    assert_eq!(model.empty_hint, None);
}

#[test]
fn one_loaded_receipt_never_claims_to_summarize_all_three() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let seeded = repeated_app(&workspace);
    let mut app = hydrated_app(&workspace);
    app.refresh_phase_attempt_projection();
    app.hydrate_view_keys_blocking(
        workspace.root(),
        vec![ViewHydrationKey::ScanStageReceipt {
            run_id: "parent-3".into(),
        }],
    );
    let model = scan_phase_model(&app);
    assert!(!model.plan.starts_with("3 scan runs"));
    assert!(model
        .empty_hint
        .as_deref()
        .unwrap()
        .contains("has not been loaded"));
    assert_eq!(scan_phase_model(&seeded).engine_outcomes.len(), 3);
}
