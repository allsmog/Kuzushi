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
