use super::scan_phase_model;
use super::LiveScanModel;
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

mod partial_membership;
mod receipt_loading;
mod repeated;
mod result_ownership;

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
    assert_eq!(
        model.scope, "not recorded",
        "A workspace target does not establish discovery scope"
    );
}

/// Issue #172 (2026-09-28 audit): `secret-scan` recorded 27 emitted findings
/// while the ledger held the 25 distinct findings they folded into, and the
/// delta panel printed the first as its total next to a breakdown of the
/// second. Both numbers are real; only one of them is the attempt's findings.
#[test]
fn attempt_findings_match_their_own_severity_breakdown_and_name_the_observations() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    write_map_and_scan_summaries(target.path());

    let mut app = hydrated_app(&workspace);
    app.set_findings(ledger_findings("scan-run", 2, 1));
    let attempt = scan_phase_model(&app).attempt.expect("scan attempt");

    assert_eq!(attempt.findings, Some(3));
    assert_eq!(attempt.findings_observed, None);
    assert_eq!(
        attempt.severity_counts,
        vec![("high".to_string(), 2), ("medium".to_string(), 1)]
    );

    // The same runs, now with one more observation recorded than the ledger
    // folded into findings.
    app.set_findings(ledger_findings("scan-run", 1, 1));
    let attempt = scan_phase_model(&app).attempt.expect("scan attempt");

    assert_eq!(attempt.findings, Some(2));
    assert_eq!(attempt.findings_observed, Some(3));
    let breakdown: u64 = attempt.severity_counts.iter().map(|(_, count)| count).sum();
    assert_eq!(breakdown, 2);
}

/// A clamped ledger holds only part of the target's findings, so counting the
/// rows it attributes to these runs would report a floor as a count. The
/// recorded summary count stands alone instead, and no breakdown is claimed.
#[test]
fn a_partial_ledger_claims_neither_a_distinct_count_nor_a_breakdown() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    write_map_and_scan_summaries(target.path());

    let mut app = hydrated_app(&workspace);
    app.set_findings(ledger_findings("scan-run", 1, 1));
    app.set_findings_total_count(9);
    let attempt = scan_phase_model(&app).attempt.expect("scan attempt");

    assert_eq!(attempt.findings, Some(3), "the recorded count is unchanged");
    assert_eq!(attempt.findings_observed, None);
    assert!(attempt.severity_counts.is_empty());
}

/// A Review filter narrows the loaded ledger without making it *look* partial
/// — `replace_filtered_findings` sets the total to the matching count — so a
/// filter would otherwise shrink what an accepted attempt is recorded as
/// having found. Counts come from the unfiltered ledger or not at all.
/// Reported by Codex review on 0708a48.
#[test]
fn a_review_filter_never_moves_what_an_accepted_attempt_found() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    write_map_and_scan_summaries(target.path());

    let mut app = hydrated_app(&workspace);
    app.set_findings(ledger_findings("scan-run", 2, 1));
    let unfiltered = scan_phase_model(&app).attempt.expect("scan attempt");
    assert_eq!(unfiltered.findings, Some(3));

    // The operator filters Review down to the one high finding. The ledger
    // now holds a subset whose total matches its length.
    app.set_findings(ledger_findings("scan-run", 1, 0));
    app.set_active_findings_filter(Some("severity:high".to_string()));
    let filtered = scan_phase_model(&app).attempt.expect("scan attempt");

    assert!(!app.findings_are_partial());
    assert_eq!(
        filtered.findings,
        Some(3),
        "the recorded count, not the filter's 1"
    );
    assert_eq!(filtered.findings_observed, None);
    assert!(filtered.severity_counts.is_empty());
}

/// A finding re-observed by a later run keeps that run as its representative
/// `scan_id` while the run that first found it stays in `sources`. Attributing
/// by the representative alone drops it from the earlier attempt, undercounting
/// that attempt and reading the recorded count's excess as corroboration.
/// Reported by Codex review on 0708a48.
#[test]
fn a_finding_a_later_run_re_observed_still_counts_for_the_run_that_found_it() {
    use kuzushi_core::findings::FindingSource;

    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    write_map_and_scan_summaries(target.path());

    let mut app = hydrated_app(&workspace);
    let mut findings = ledger_findings("scan-run", 2, 0);
    // A later run re-observed the third finding; `scan-run` found it first.
    let mut reobserved = ledger_findings("later-run", 0, 1).remove(0);
    reobserved.sources = vec![FindingSource {
        tool: "secret-scan".to_string(),
        vuln_source: None,
        source_signature: "sig".to_string(),
        first_scan_id: "scan-run".to_string(),
        last_scan_id: "later-run".to_string(),
        first_seen_at: "2026-09-29T00:00:00Z".to_string(),
        last_seen_at: "2026-09-29T01:00:00Z".to_string(),
    }];
    findings.push(reobserved);
    app.set_findings(findings);
    let attempt = scan_phase_model(&app).attempt.expect("scan attempt");

    assert_eq!(attempt.findings, Some(3));
    assert_eq!(attempt.findings_observed, None, "3 recorded, 3 attributed");
    assert_eq!(
        attempt.severity_counts,
        vec![("high".to_string(), 2), ("medium".to_string(), 1)]
    );
}

fn ledger_findings(scan_id: &str, high: u32, medium: u32) -> Vec<kuzushi_core::findings::Finding> {
    use kuzushi_core::findings::{Finding, Severity};
    (0..high)
        .map(|index| (index, Severity::High))
        .chain((0..medium).map(|index| (high + index, Severity::Medium)))
        .map(|(index, severity)| {
            let mut finding = Finding::new_tool(
                "secret-scan",
                format!("rule-{index}"),
                format!("src/file{index}.rs"),
                index + 1,
                None,
                severity,
                "ledger row",
            );
            finding.scan_id = Some(scan_id.to_string());
            finding
        })
        .collect()
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
    assert_eq!(model.scope, "not recorded");
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

/// Issue #172 ([HIGH], reconfirmed 2026-10-10): on the typed-receipt path the
/// panel read `findings +31 added · 0 updated` over its own `20 high ·
/// 5 medium · 4 low` breakdown of the 29 findings the ledger attributes to
/// the same runs. The renderer already falls back to the reconciled pair when
/// the delta is absent; the builder never made it absent, so the recorded
/// fingerprint delta always won the match and the breakdown beside it came
/// from different evidence.
#[test]
fn a_typed_delta_the_ledger_folded_yields_to_the_count_its_breakdown_adds_up_to() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let run_id = "typed-scan-folded";
    record_typed_scan_attempt(target.path(), run_id);

    // The receipt records a 4 + 2 fingerprint delta; the ledger folded those
    // six observations into four findings.
    let mut app = app_with_hydrated_typed_attempt(&workspace, run_id);
    app.set_findings(ledger_findings(run_id, 3, 1));
    let attempt = scan_phase_model(&app).attempt.expect("typed Scan attempt");

    assert_eq!(attempt.findings_added, None);
    assert_eq!(attempt.findings_updated, None);
    assert_eq!(attempt.findings, Some(4));
    assert_eq!(attempt.findings_observed, Some(6));
    let breakdown: u64 = attempt.severity_counts.iter().map(|(_, count)| count).sum();
    assert_eq!(
        breakdown,
        attempt.findings.unwrap(),
        "the breakdown must add up to the total beside it: {:?}",
        attempt.severity_counts
    );
}

/// The reconciliation only withholds a delta that stopped counting findings.
/// A recorded delta the ledger agrees with still reaches the panel, so an
/// attempt does not lose its `added`/`updated` split to a defensive rule.
#[test]
fn a_typed_delta_the_ledger_agrees_with_still_reaches_the_panel() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let run_id = "typed-scan-agreed";
    record_typed_scan_attempt(target.path(), run_id);

    let mut app = app_with_hydrated_typed_attempt(&workspace, run_id);
    app.set_findings(ledger_findings(run_id, 4, 2));
    let attempt = scan_phase_model(&app).attempt.expect("typed Scan attempt");

    assert_eq!(attempt.findings_added, Some(4));
    assert_eq!(attempt.findings_updated, Some(2));
    assert_eq!(attempt.findings, Some(6));
    assert_eq!(attempt.findings_observed, None);
}

/// Withholding the split must not take the panel with it. `scan_has_delta`
/// read only the `added`/`updated` pair, artifacts, and the error, so an
/// attempt that recorded no artifact lost the whole FINDING / ARTIFACT DELTA
/// surface at the moment the reconciliation made it read honestly — and with
/// it the reconciled total and the breakdown. AGENTS.md owes the Scan cockpit
/// its finding delta. Reported by Codex review on `ac22d186`.
#[test]
fn an_artifact_free_folded_attempt_keeps_its_delta_surface() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let run_id = "typed-scan-no-artifacts";
    record_typed_scan_attempt(target.path(), run_id);

    // Re-publish the receipt with no artifact delta, so the surface has only
    // the finding evidence to stand on.
    let mut receipt = kuzushi_core::run_artifacts::load_scan_stage_data(target.path(), run_id)
        .unwrap()
        .unwrap();
    let scan = receipt.scan.as_mut().unwrap();
    scan.artifact_delta.clear();
    crate::test_support::record_indexed_run(
        target.path(),
        run_id,
        "sast:scan",
        serde_json::json!({"ok": true, "data": {"phaseStages": [receipt]}}),
    );

    let mut app = app_with_hydrated_typed_attempt(&workspace, run_id);
    app.set_findings(ledger_findings(run_id, 3, 1));
    let model = scan_phase_model(&app);
    let attempt = model.attempt.clone().expect("typed Scan attempt");

    assert_eq!(attempt.artifact_count, 0);
    assert_eq!(attempt.error, None);
    assert_eq!(
        (attempt.findings_added, attempt.findings_updated),
        (None, None)
    );
    assert!(!attempt.severity_counts.is_empty());

    let specs = crate::ui_view_models::phase_surface_specs(
        &crate::ui_view_models::PhaseCockpitBody::Scan(model),
    );
    assert!(
        specs
            .iter()
            .any(|spec| spec.id == crate::ui_view_models::PhaseSurfaceId::ScanDelta),
        "the delta surface must survive a withheld split: {:?}",
        specs.iter().map(|spec| spec.id).collect::<Vec<_>>()
    );
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
                inspected_files: None,
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
                    rule_ids: None,
                    run_ref: Some("semgrep-child".to_string()),
                    detail: None,
                },
                ScanStageEngine {
                    engine: "cargo-audit".to_string(),
                    outcome: ScanEngineStageOutcome::Skipped,
                    rule_ids: None,
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

#[test]
fn scan_panel_running_state_projects_the_live_run() {
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    assert_eq!(scan_phase_model(&app).live, None);

    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("run-live".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "scanning".to_string(),
        findings_count: 2,
        running: true,
        abort_requested: false,
        error: None,
    }));
    assert_eq!(
        scan_phase_model(&app).live,
        Some(LiveScanModel {
            run_id: Some("run-live".to_string()),
            stage: "scanning".to_string(),
            findings: 2,
        })
    );

    app.scan_mut().unwrap().running = false;
    assert_eq!(scan_phase_model(&app).live, None);
}

#[test]
fn canceled_attempts_label_stopped_engines_without_relabeling_completed_work() {
    use super::typed_engine_outcome;
    let attempt = PhaseAttemptOutcome::Canceled;
    assert_eq!(
        typed_engine_outcome(ScanEngineStageOutcome::Failed, attempt),
        "stopped"
    );
    assert_eq!(
        typed_engine_outcome(ScanEngineStageOutcome::Complete, attempt),
        "complete"
    );
    assert_eq!(
        typed_engine_outcome(ScanEngineStageOutcome::Partial, attempt),
        "partial"
    );
    assert_eq!(
        typed_engine_outcome(ScanEngineStageOutcome::Skipped, attempt),
        "skipped"
    );
    assert_eq!(
        typed_engine_outcome(ScanEngineStageOutcome::Failed, PhaseAttemptOutcome::Failed),
        "failed"
    );
}
