use super::*;
use kuzushi_core::run_artifacts::*;
use kuzushi_core::workflow_attempts::{PhaseAttemptOutcome, PhaseTargetSnapshot};
use std::fs;

fn parent_receipt(target: &Path) -> PhaseStageReceipt {
    PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Completed,
        run_refs: vec!["engine-child".into()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                target: target.display().to_string(),
                paths: Vec::new(),
            },
            plan: ScanStagePlan {
                selection: "manual".into(),
                engines: vec!["agentic".into()],
            },
            engines: Vec::new(),
            finding_delta: ScanFindingDelta {
                added: 1,
                updated: 0,
            },
            severity_counts: Vec::new(),
            artifact_delta: Vec::new(),
            duration_ms: 1,
            cost: None,
            target_snapshot: PhaseTargetSnapshot::capture(target),
        }),
    }
}

fn select_attempt(target: &Path, phase: WorkflowPhase, run: &str) {
    let completed = crate::test_support::append_typed_attempt(
        target,
        phase,
        run,
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target, &completed);
}

#[test]
fn selected_parent_counts_its_engine_findings_and_excludes_unrelated_history() {
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("lib.rs"), "fn greeting() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for run in ["unrelated-history", "engine-child"] {
        store
            .record_run_started(run, target.path(), "running")
            .unwrap();
        let mut finding = Finding::new_tool(
            "fixture",
            run,
            "lib.rs",
            1,
            None,
            Severity::Low,
            "labeled fixture observation",
        );
        finding.fingerprint = run.into();
        store.insert_finding(run, &finding).unwrap();
    }
    crate::test_support::record_indexed_run(
        target.path(),
        "map-parent",
        "context:build",
        serde_json::json!({"ok":true,"data":{}}),
    );
    select_attempt(target.path(), WorkflowPhase::Map, "map-parent");
    crate::test_support::record_indexed_run(
        target.path(),
        "scan-parent",
        "sast:scan",
        serde_json::json!({"ok":true,"data":{"phaseStages":[parent_receipt(target.path())]}}),
    );
    select_attempt(target.path(), WorkflowPhase::Scan, "scan-parent");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    assert_eq!(
        app.selected_current_scan_run_refs(),
        Some(vec!["scan-parent".into()])
    );
    let current = app
        .relevant_journey_findings(&store, IdentityFoldPolicy::Legacy)
        .unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].fingerprint, "engine-child");
    let operator = tempfile::tempdir().unwrap();
    app.refresh_findings_with_operator_state(false, operator.path());
    assert_eq!(app.domain().finding_ledger_counts().unwrap().total, 1);
    assert_eq!(
        app.findings().len(),
        2,
        "the history remains in the authoritative ledger"
    );
    fs::write(
        run_dir(target.path(), "scan-parent").join("result.json"),
        "damaged",
    )
    .unwrap();
    app.refresh_findings_with_operator_state(false, operator.path());
    assert_eq!(
        app.domain().finding_ledger_counts().unwrap().total,
        2,
        "a damaged receipt must never forge clean Scan"
    );
}
