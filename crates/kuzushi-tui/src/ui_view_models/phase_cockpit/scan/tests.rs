use super::scan_phase_model;
use crate::{ShellApp, ViewHydrationKey};
use kuzushi_core::run_artifacts::{
    PhaseStageOutcome, PhaseStageReceipt, ScanArtifactDelta, ScanEngineStageOutcome,
    ScanFindingDelta, ScanSeverityCount, ScanStageCost, ScanStageData, ScanStageEngine,
    ScanStagePlan, ScanStageScope, SAST_PHASE_STAGES_JSONL_FILE,
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
    assert_eq!(model.engine_outcomes[0].engine, "Run SAST scan");
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
    record_typed_scan_attempt(target.path(), run_id);

    let app = app_with_hydrated_typed_attempt(&workspace, run_id);
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
    assert_eq!(
        attempt.severity_counts,
        vec![
            ("critical".to_string(), 1),
            ("high".to_string(), 2),
            ("medium".to_string(), 3),
        ],
        "typed receipt severity buckets must reach the cockpit highest-first"
    );
}

/// Regression: an external workspace refresh invalidates the run-summary
/// index and view caches on every writer burst. The typed attempt card must
/// hold steady — no downgrade to the legacy projection, no transient
/// "receipts are loading" hint flapping beneath it.
#[test]
fn typed_projection_survives_external_cache_invalidation_without_hint_flap() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let run_id = "typed-scan-stable";
    record_typed_scan_attempt(target.path(), run_id);
    let app = app_with_hydrated_typed_attempt(&workspace, run_id);
    let before = scan_phase_model(&app);
    assert!(before.attempt.is_some(), "typed attempt before refresh");
    assert_eq!(before.empty_hint, None);

    app.workbench_cache()
        .borrow_mut()
        .invalidate_workspace_files();
    app.workbench_cache()
        .borrow_mut()
        .invalidate_state_artifact_paths(
            workspace.root(),
            &[std::path::PathBuf::from(".kuzushi/v3")],
        );

    let after = scan_phase_model(&app);
    assert_eq!(after.plan, before.plan, "typed plan must not downgrade");
    assert_eq!(after.attempt, before.attempt);
    assert_eq!(after.engine_outcomes, before.engine_outcomes);
    assert_eq!(after.empty_hint, None, "no loading hint under a typed card");
}

/// Regression: attempts with no typed receipt (direct engine runs) project
/// from the run-summary index. That index now serves stale entries while it
/// rehydrates, so the legacy card must also hold steady across an external
/// workspace refresh instead of degrading to "plan not recorded".
#[test]
fn legacy_projection_survives_external_cache_invalidation() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let scan = write_partial_scan(target.path());
    select_partial_attempt(target.path(), &scan);
    let mut app = hydrated_app(&workspace);
    app.refresh_phase_attempt_projection();
    let before = scan_phase_model(&app);
    assert!(before.attempt.is_some(), "legacy attempt before refresh");

    app.workbench_cache()
        .borrow_mut()
        .invalidate_state_artifact_paths(
            workspace.root(),
            &[std::path::PathBuf::from(".kuzushi/v3")],
        );

    let after = scan_phase_model(&app);
    assert_eq!(after.plan, before.plan, "legacy plan must not degrade");
    assert_eq!(after.attempt, before.attempt);
    assert_eq!(after.engine_outcomes, before.engine_outcomes);
    assert_eq!(after.empty_hint, before.empty_hint);
}

fn record_typed_scan_attempt(target: &std::path::Path, run_id: &str) {
    let mut summary = RunSummary::running(
        run_id,
        "scan",
        Some("sast:scan".to_string()),
        target.display().to_string(),
    );
    summary.status = "partial".to_string();
    summary.completed_at_unix = Some(summary.started_at_unix + 99);
    write_run_summary(target, &summary).unwrap();
    let snapshot = PhaseTargetSnapshot::capture(target);
    let receipt = PhaseStageReceipt {
        phase: WorkflowPhase::Scan,
        outcome: PhaseStageOutcome::Partial,
        run_refs: vec![run_id.to_string(), "semgrep-child".to_string()],
        scan: Some(ScanStageData {
            scope: ScanStageScope {
                target: target.display().to_string(),
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
            severity_counts: vec![
                ScanSeverityCount {
                    severity: kuzushi_core::findings::Severity::Critical,
                    count: 1,
                },
                ScanSeverityCount {
                    severity: kuzushi_core::findings::Severity::High,
                    count: 2,
                },
                ScanSeverityCount {
                    severity: kuzushi_core::findings::Severity::Medium,
                    count: 3,
                },
            ],
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
    let stage_path =
        kuzushi_core::run_artifacts::run_dir(target, run_id).join(SAST_PHASE_STAGES_JSONL_FILE);
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
    append_phase_attempt_completed(target, completed).unwrap();
}

fn app_with_hydrated_typed_attempt(workspace: &WorkspaceTarget, run_id: &str) -> ShellApp {
    let mut app = hydrated_app(workspace);
    app.refresh_phase_attempt_projection();
    app.hydrate_view_keys_blocking(
        workspace.root(),
        vec![ViewHydrationKey::ScanStageReceipt {
            run_id: run_id.to_string(),
        }],
    );
    app
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
