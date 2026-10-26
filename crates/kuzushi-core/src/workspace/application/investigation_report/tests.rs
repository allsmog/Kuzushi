use super::*;
use crate::capabilities::campaign::{
    compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
};
use crate::modules::ModuleRegistry;

mod attempt_status;
mod context_guidance;
mod matrix;
mod reassessment;
mod review_counts;
mod scope;

pub(in crate::workspace::application) fn planned_report(root: &Path) -> InvestigationReportReceipt {
    let workspace = WorkspaceTarget::new(root).unwrap();
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root,
        batch_id: Some("report-study".into()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"taskMode":"manual","tasks":["secret-scan"], "paths":["src"]}),
        config: &crate::V2Config::default(),
        registry: &ModuleRegistry::with_v2_builtins(),
    })
    .unwrap();
    load_investigation_report(&workspace, "report-study").unwrap()
}

#[test]
fn unexecuted_study_is_pending_not_clean_coverage() {
    let target = tempfile::tempdir().unwrap();
    let report = planned_report(target.path());
    assert_eq!(
        (
            report.occurrence.planned,
            report.occurrence.pending,
            report.occurrence.completed
        ),
        (3, 3, 0)
    );
    assert_eq!(report.scope["paths"], json!(["src"]));
    assert!(report.allowance.is_none());
    assert_eq!(report.observation_count, 0);
    assert!(report
        .limitations
        .iter()
        .any(|s| s.contains("never establishes a fix")));
    assert!(
        load_investigation_report(&WorkspaceTarget::new(target.path()).unwrap(), "../other")
            .is_err()
    );
}

#[test]
fn study_export_cannot_include_unrelated_workspace_findings() {
    let target = tempfile::tempdir().unwrap();
    planned_report(target.path());
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = Finding::new_tool(
        "scanner",
        "rule",
        "other.rs",
        1,
        None,
        crate::Severity::High,
        "historical finding",
    );
    store
        .record_run_started("historical-run", target.path(), "completed")
        .unwrap();
    store.insert_findings("historical-run", &[finding]).unwrap();
    let options = WorkspaceExportOptions::default().with_campaign(Some("report-study".into()));
    let preview =
        preview_workspace_findings_export(&workspace, WorkspaceExportFormat::Json, &options)
            .unwrap();
    assert_eq!((preview.count, preview.total_count), (0, 0));
    assert_eq!(preview.investigation.unwrap()["occurrence"]["pending"], 3);
    let history = preview_workspace_findings_export(
        &workspace,
        WorkspaceExportFormat::Json,
        &WorkspaceExportOptions::default(),
    )
    .unwrap();
    assert_eq!(history.count, 1);
    assert!(history.investigation.is_none());
}

#[test]
fn prepared_export_resolves_campaign_alias_and_keeps_the_study_receipt() {
    let target = tempfile::tempdir().unwrap();
    planned_report(target.path());
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let config = crate::V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    assert_eq!(
        registry
            .resolve_tool("workspace:export-findings")
            .unwrap()
            .phase,
        crate::modules::ToolPhase::Report
    );
    let ctx = crate::modules::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(
            "workspace:export-findings",
            json!({"output":"module-study.json", "campaign_id":"report-study", "allowEmpty":true}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["status"], "completed");
    let receipt_path = result["data"]["investigationReceiptPath"].as_str().unwrap();
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["campaignId"], "report-study");
    assert_eq!(receipt["occurrence"]["pending"], 3);
}
