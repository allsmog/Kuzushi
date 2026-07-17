use super::scan_phase_model;
use crate::{ShellApp, ViewHydrationKey};
use kuzushi_core::run_artifacts::{
    PhaseStageOutcome, PhaseStageReceipt, ScanArtifactDelta, ScanEngineStageOutcome,
    ScanFindingDelta, ScanStageCost, ScanStageData, ScanStageEngine, ScanStagePlan, ScanStageScope,
    SAST_PHASE_STAGES_JSONL_FILE,
};
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, append_phase_attempt_disposition, PhaseAttemptCompleted,
    PhaseAttemptDisposition, PhaseAttemptDispositionRecorded, PhaseAttemptOutcome,
    PhaseTargetSnapshot,
};
use kuzushi_core::{write_run_summary, RunSummary, V2Config, WorkflowPhase, WorkspaceTarget};

#[test]
fn missing_target_discloses_unloaded_scan_receipts() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = scan_phase_model(&app);

    assert_eq!(model.scope, "no target selected");
    assert!(model.attempt.is_none());
    assert_eq!(
        model.empty_hint.as_deref(),
        Some("Scan receipts have not been loaded for this target")
    );
}

#[test]
fn projects_only_terminal_scan_phase_runs() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    write_map_and_scan_summaries(target.path());

    let app = hydrated_app(&workspace);
    let model = scan_phase_model(&app);
    let attempt = model.attempt.expect("scan attempt");

    assert_eq!(attempt.disposition, "legacy inferred");
    assert_eq!(attempt.run_id, "scan-run");
    assert_eq!(attempt.findings, Some(3));
    assert_eq!(attempt.duration_secs, Some(9));
    assert_eq!(model.engine_outcomes[0].engine, "sast:scan");
}

fn write_map_and_scan_summaries(target: &std::path::Path) {
    let map = RunSummary::running(
        "map-run",
        "tool",
        Some("context:build".to_string()),
        target.display().to_string(),
    )
    .complete();
    write_run_summary(target, &map).unwrap();
    let mut scan = RunSummary::running(
        "scan-run",
        "scan",
        Some("sast:scan".to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(Some(3));
    scan.completed_at_unix = Some(scan.started_at_unix + 9);
    write_run_summary(target, &scan).unwrap();
}

#[test]
fn selected_partial_attempt_discloses_acknowledgement() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let scan = write_partial_scan(target.path());
    let completed = select_partial_attempt(target.path(), &scan);

    let mut app = hydrated_app(&workspace);
    app.refresh_phase_attempt_projection();
    let model = scan_phase_model(&app);
    let attempt = model.attempt.expect("selected Scan attempt");

    assert_eq!(
        attempt.attempt_id.as_deref(),
        Some(completed.attempt_id.as_str())
    );
    assert_eq!(attempt.outcome, "partial");
    assert_eq!(attempt.disposition, "selected · partial acknowledged");
    assert_eq!(model.engine_outcomes[0].outcome, "partial");
}

#[test]
fn durable_scan_stage_projects_typed_scope_plan_engine_and_deltas() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let run_id = "typed-scan-cockpit";
    let mut summary = RunSummary::running(
        run_id,
        "scan",
        Some("sast:scan".to_string()),
        target.path().display().to_string(),
    );
    summary.status = "partial".to_string();
    summary.completed_at_unix = Some(summary.started_at_unix + 99);
    write_run_summary(target.path(), &summary).unwrap();
    let snapshot = PhaseTargetSnapshot::capture(target.path());
    let receipt = PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Partial,
        run_refs: vec![run_id.to_string(), "semgrep-child".to_string()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                target: target.path().display().to_string(),
                paths: vec!["src/auth".to_string()],
            },
            plan: ScanStagePlan {
                selection: "manual".to_string(),
                engines: vec!["semgrep".to_string(), "cargo-audit".to_string()],
            },
            engines: vec![
                ScanStageEngine {
                    engine: "semgrep".to_string(),
                    outcome: ScanEngineStageOutcome::Complete,
                    run_ref: Some("semgrep-child".to_string()),
                    detail: None,
                },
                ScanStageEngine {
                    engine: "cargo-audit".to_string(),
                    outcome: ScanEngineStageOutcome::Skipped,
                    run_ref: None,
                    detail: Some("binary unavailable".to_string()),
                },
            ],
            finding_delta: ScanFindingDelta {
                added: 4,
                updated: 2,
            },
            artifact_delta: vec![ScanArtifactDelta {
                run_ref: "semgrep-child".to_string(),
                path: "result.json".to_string(),
            }],
            duration_ms: 1_250,
            cost: Some(ScanStageCost {
                observed_usd: 0.5,
                complete: false,
            }),
            target_snapshot: snapshot.clone(),
        }),
    };
    let stage_path = kuzushi_core::run_artifacts::run_dir(target.path(), run_id)
        .join(SAST_PHASE_STAGES_JSONL_FILE);
    std::fs::create_dir_all(stage_path.parent().unwrap()).unwrap();
    std::fs::write(
        &stage_path,
        format!("{}\n", serde_json::to_string(&receipt).unwrap()),
    )
    .unwrap();
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec![run_id.to_string()],
        snapshot,
        PhaseAttemptOutcome::Partial,
    );
    append_phase_attempt_completed(target.path(), completed).unwrap();

    let mut app = hydrated_app(&workspace);
    app.refresh_phase_attempt_projection();
    app.hydrate_view_keys_blocking(
        workspace.root(),
        vec![ViewHydrationKey::ScanStageReceipt {
            run_id: run_id.to_string(),
        }],
    );
    let model = scan_phase_model(&app);
    let attempt = model.attempt.expect("typed Scan attempt");

    assert!(model.scope.contains("paths src/auth"));
    assert_eq!(
        model.plan,
        "manual selection · semgrep, cargo-audit".to_string()
    );
    assert_eq!(model.engine_outcomes[0].outcome, "complete");
    assert_eq!(
        model.engine_outcomes[0].run_ref.as_deref(),
        Some("semgrep-child")
    );
    assert_eq!(model.engine_outcomes[1].outcome, "skipped");
    assert_eq!(attempt.outcome, "partial");
    assert_eq!(attempt.findings_added, Some(4));
    assert_eq!(attempt.findings_updated, Some(2));
    assert_eq!(attempt.findings, Some(6));
    assert_eq!(attempt.artifact_count, 1);
    assert_eq!(
        attempt.artifact_paths,
        vec!["semgrep-child:result.json".to_string()]
    );
    assert_eq!(attempt.duration_secs, Some(2));
    assert_eq!(attempt.cost_complete, Some(false));
}

fn write_partial_scan(target: &std::path::Path) -> RunSummary {
    crate::test_support::record_indexed_run(
        target,
        "scan-partial",
        "semgrep:scan",
        serde_json::json!({
            "ok": true,
            "status": "partial",
            "summary": "partial scan",
            "warnings": ["one scanner was incomplete"],
            "data": {"count": 2}
        }),
    );
    let mut scan = kuzushi_core::load_run_summary(target, "scan-partial")
        .unwrap()
        .with_findings(Some(2));
    scan.completed_at_unix = Some(scan.started_at_unix + 4);
    write_run_summary(target, &scan).unwrap();
    scan
}

fn select_partial_attempt(target: &std::path::Path, scan: &RunSummary) -> PhaseAttemptCompleted {
    let completed = crate::test_support::append_typed_attempt(
        target,
        WorkflowPhase::Scan,
        &scan.run_id,
        PhaseAttemptOutcome::Partial,
    );
    crate::test_support::select_typed_attempt(target, &completed);
    completed
}

fn hydrated_app(workspace: &WorkspaceTarget) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), Some(workspace));
    app.hydrate_view_keys_blocking(workspace.root(), vec![ViewHydrationKey::RunSummaryEntries]);
    app
}
