use super::*;
use crate::findings::{BatchTrialReport, IdentityFoldPolicy};
use serde_json::json;

fn fixture(
    state: &str,
) -> (
    tempfile::TempDir,
    Value,
    BatchOccurrenceReport,
    ScanBatchGateOutcome,
) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".kuzushi/v3/campaigns/owned");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("queue.json"),
        json!({"jobs":{"trial":{"state":state}}}).to_string(),
    )
    .unwrap();
    let plan = json!({"jobs":[{"jobId":"trial","trial":1}]});
    let report = BatchOccurrenceReport {
        schema_version: 1,
        batch_id: "owned".into(),
        equivalence_key: "eq".into(),
        identity_fold: IdentityFoldPolicy::Safe,
        planned: 1,
        completed: 0,
        failed: 0,
        pending: 1,
        gate: None,
        rows: vec![],
        trials: vec![BatchTrialReport {
            trial: 1,
            job_id: "trial".into(),
            state: "planned".into(),
            attempts: 0,
            run_id: None,
            attempt_run_ids: vec![],
            finding_run_ids: vec!["child".into()],
            failure_reason: None,
        }],
    };
    let outcome = ScanBatchGateOutcome::new(
        "owned",
        "eq",
        &Default::default(),
        crate::capabilities::campaign::ScanBatchGateCounts {
            planned_trials: 1,
            completed_trials: 0,
            failed_trials: 0,
            pending_trials: 1,
            completed_run_ids: vec![],
            blocking_safe_fold_count: 0,
            sarif_written: false,
        },
        binding("recorded"),
    );
    (root, plan, report, outcome)
}

fn binding(state: &str) -> ScanBatchGateBinding {
    ScanBatchGateBinding {
        logical_terminal_state_sha256: format!("sha256:{state}"),
        blocking_findings_sha256: "sha256:findings".into(),
        sarif_path: None,
        sarif_sha256: None,
    }
}

#[test]
fn a_changed_queue_requests_a_new_snapshot_without_accepting_the_assessment() {
    let (root, plan, report, outcome) = fixture("running");
    let error = validate(
        root.path(),
        &plan,
        &report,
        &outcome,
        (binding("current"), 0),
    )
    .unwrap_err();
    assert!(error.is::<BatchReceiptPending>());
    assert!(report.gate.is_none());
}

#[test]
fn stable_mismatches_remain_errors_and_hydrated_child_refs_do_not_fake_a_queue_update() {
    let (root, plan, report, outcome) = fixture("planned");
    let error = validate(
        root.path(),
        &plan,
        &report,
        &outcome,
        (binding("current"), 0),
    )
    .unwrap_err();
    assert!(!error.is::<BatchReceiptPending>());
    assert!(error.to_string().contains("batch gate is stale"));
}

#[test]
fn a_matching_assessment_keeps_its_existing_snapshot() {
    let (root, plan, report, outcome) = fixture("running");
    validate(
        root.path(),
        &plan,
        &report,
        &outcome,
        (outcome.binding.clone(), 0),
    )
    .unwrap();
}

#[test]
fn owned_publication_waits_without_accepting_a_stable_mismatch() {
    let (root, plan, report, outcome) = fixture("planned");
    let lease = crate::capabilities::campaign::acquire_batch_controller_lease(root.path(), "owned")
        .unwrap();
    let error = validate(
        root.path(),
        &plan,
        &report,
        &outcome,
        (binding("current"), 0),
    )
    .unwrap_err();
    assert!(error.is::<BatchReceiptPending>());
    assert!(report.gate.is_none());
    drop(lease);
    let error = validate(
        root.path(),
        &plan,
        &report,
        &outcome,
        (binding("current"), 0),
    )
    .unwrap_err();
    assert!(!error.is::<BatchReceiptPending>());
    assert!(error.to_string().contains("batch gate is stale"));
}

#[test]
fn malformed_queue_metadata_is_not_a_retryable_update() {
    let (root, plan, report, outcome) = fixture("planned");
    let _lease =
        crate::capabilities::campaign::acquire_batch_controller_lease(root.path(), "owned")
            .unwrap();
    std::fs::write(
        root.path().join(".kuzushi/v3/campaigns/owned/queue.json"),
        b"broken",
    )
    .unwrap();
    let error = validate(
        root.path(),
        &plan,
        &report,
        &outcome,
        (binding("current"), 0),
    )
    .unwrap_err();
    assert!(!error.is::<BatchReceiptPending>());
    assert!(error.to_string().contains("malformed JSON"));
}
