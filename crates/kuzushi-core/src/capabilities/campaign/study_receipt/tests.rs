use super::*;
use crate::{modules::ModuleRegistry, V2Config};
use serde_json::json;

fn draft(root: &Path) -> CampaignPlanHandle {
    super::super::batch::compile_study_plan(
        ScanBatchPlanSpec {
            root,
            batch_id: Some("study".into()),
            trials: 3,
            requested_workers: 1,
            gate_policy: ScanBatchGatePolicy::default(),
            prepared_input: json!({"taskMode":"manual","tasks":["secret-scan"]}),
            config: &V2Config::default(),
            registry: &ModuleRegistry::with_v2_builtins(),
        },
        Some("investigation"),
    )
    .unwrap()
}

#[test]
fn receipt_round_trip_preserves_exact_jobs_input_and_accounting_identity() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("source.rs"), "fn main() {}\n").unwrap();
    let handle = draft(target.path());
    let receipt = load_study_plan_receipt(target.path(), "study").unwrap();
    assert_eq!(receipt.equivalence, handle.equivalence_key);
    assert_eq!(receipt.investigation_id.as_deref(), Some("investigation"));
    assert_eq!((receipt.job_count, receipt.workers), (3, 1));
    assert!(receipt.approval_required);
    assert_eq!(
        receipt.plan_sha256,
        campaign_plan_digest(target.path(), "study").unwrap()
    );
    assert_eq!(receipt.scan_input["triage"], false);
    assert!(receipt.scan_input["threatModelRef"].is_null());
    assert!(load_study_allowance(target.path(), &receipt)
        .unwrap()
        .is_none());
    assert_eq!(
        receipt,
        serde_json::from_value(serde_json::to_value(&receipt).unwrap()).unwrap()
    );
}

#[test]
fn tampered_jobs_and_invalid_paths_cannot_be_presented_as_reviewable() {
    let target = tempfile::tempdir().unwrap();
    let handle = draft(target.path());
    let mut document: Value =
        serde_json::from_slice(&std::fs::read(&handle.plan_path).unwrap()).unwrap();
    document["jobs"][0]["input"]["triage"] = json!(true);
    std::fs::write(&handle.plan_path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(load_study_plan_receipt(target.path(), "study").is_err());
    assert!(load_study_plan_receipt(target.path(), "../study").is_err());
}

#[test]
fn usage_baseline_is_frozen_outside_scan_options_and_authenticated_after_restart() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("source.rs"), "fn main() {}\n").unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = crate::modules::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"campaignId":"usage-plan","baseline_run_id":"recorded-baseline","scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}});
    let prepared = registry
        .prepare_dispatch_input("campaign:study", input, &ctx, None)
        .unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(output["data"]["resourceBaselineRunId"], "recorded-baseline");
    let receipt = load_study_plan_receipt(root.path(), "usage-plan").unwrap();
    assert_eq!(
        load_study_resource_baseline(root.path(), &receipt)
            .unwrap()
            .as_deref(),
        Some("recorded-baseline")
    );
    assert!(receipt.scan_input.get("baselineRunId").is_none());
    assert!(!root.path().join(".kuzushi/v3/index.sqlite3").exists());
    let mut document: Value =
        serde_json::from_slice(&std::fs::read(&receipt.plan_path).unwrap()).unwrap();
    document["resourceBaselineRunId"] = json!("different-baseline");
    std::fs::write(&receipt.plan_path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(load_study_resource_baseline(root.path(), &receipt).is_err());
    let invalid = json!({"campaignId":"bad-baseline","baselineRunId":"../outside","scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null}});
    let prepared = registry
        .prepare_dispatch_input("campaign:study", invalid, &ctx, None)
        .unwrap();
    assert!(registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .is_err());
    assert!(!campaign_plan_path(root.path(), "bad-baseline").exists());
}
