use super::*;
use crate::capabilities::campaign::ScanBatchGateBinding;
use crate::findings::{Finding, FindingIdentityBasis, FindingStore, Severity};
use serde_json::json;
use std::path::Path;

#[test]
fn gate_receipt_must_match_batch_equivalence_and_frozen_policy() {
    use crate::capabilities::campaign::{
        ScanBatchGateCounts, ScanBatchGateOutcome, ScanBatchGatePolicy,
    };
    let policy = ScanBatchGatePolicy {
        fail_on: Some(Severity::High),
        sarif: Some(std::path::PathBuf::from("batch.sarif")),
    };
    let plan = json!({"equivalenceKey": "eq-good", "gatePolicy": policy});
    let counts = ScanBatchGateCounts {
        planned_trials: 3,
        completed_trials: 2,
        failed_trials: 1,
        pending_trials: 0,
        completed_run_ids: vec!["run-a".to_string()],
        blocking_safe_fold_count: 1,
        sarif_written: true,
    };
    let good = ScanBatchGateOutcome::new(
        "batch-test",
        "eq-good",
        &policy,
        counts.clone(),
        gate_binding(true),
    );
    validate_loaded_batch_gate("batch-test", &plan, &good).unwrap();

    let mut malformed = good.clone();
    malformed.threshold = None;
    assert!(validate_loaded_batch_gate("batch-test", &plan, &malformed).is_err());

    let wrong_batch = ScanBatchGateOutcome::new(
        "batch-other",
        "eq-good",
        &policy,
        counts.clone(),
        gate_binding(true),
    );
    assert!(validate_loaded_batch_gate("batch-test", &plan, &wrong_batch).is_err());
    let wrong_key = ScanBatchGateOutcome::new(
        "batch-test",
        "eq-other",
        &policy,
        counts.clone(),
        gate_binding(true),
    );
    assert!(validate_loaded_batch_gate("batch-test", &plan, &wrong_key).is_err());
    let wrong_policy = ScanBatchGatePolicy::default();
    let wrong_policy_receipt = ScanBatchGateOutcome::new(
        "batch-test",
        "eq-good",
        &wrong_policy,
        counts,
        gate_binding(false),
    );
    assert!(validate_loaded_batch_gate("batch-test", &plan, &wrong_policy_receipt).is_err());
}

fn gate_binding(sarif: bool) -> ScanBatchGateBinding {
    ScanBatchGateBinding {
        logical_terminal_state_sha256: "sha256:state".to_string(),
        blocking_findings_sha256: "sha256:findings".to_string(),
        sarif_path: sarif.then(|| std::path::PathBuf::from("/tmp/batch.sarif")),
        sarif_sha256: sarif.then(|| "sha256:sarif".to_string()),
    }
}

#[test]
fn retry_attempts_do_not_increase_logical_occurrence_counts() {
    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let store = FindingStore::open(target.path().join(".kuzushi/v3/findings.db")).unwrap();
    for run_id in [
        "run-trial-1-a1",
        "run-trial-1-a2",
        "run-trial-2-a1",
        "run-trial-3-a1",
        "run-trial-3-a2",
    ] {
        store
            .record_run_started(run_id, target.path(), "completed")
            .unwrap();
        write_trial_receipt(target.path(), run_id, &planned_config_sha256(target.path()));
    }
    let mut finding = Finding::new_tool(
        "semgrep",
        "rule/cwe-89",
        "src/db.rs",
        12,
        Some(12),
        Severity::High,
        "SQL injection, CWE-89",
    );
    finding.identity_id = Some("fi_retry_same_finding".to_string());
    finding.identity_basis = Some(FindingIdentityBasis::ExactProducerFingerprint);
    store.insert_finding("run-trial-1-a1", &finding).unwrap();
    store.insert_finding("run-trial-1-a2", &finding).unwrap();

    let report = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap();

    assert_eq!((report.planned, report.completed, report.failed), (3, 2, 1));
    assert_eq!(report.trials[0].attempts, 2);
    assert_eq!(report.rows.len(), 1, "{:#?}", report.rows);
    assert_eq!(report.rows[0].seen, 1);
    assert_eq!(
        report.trials[0].attempt_run_ids,
        vec!["run-trial-1-a1", "run-trial-1-a2"]
    );
    assert_eq!(report.all_attempt_run_ids().len(), 5);
    assert_eq!(report.rows[0].completed, 2);
    assert_eq!(report.rows[0].planned, 3);
    assert_eq!(report.rows[0].failed, 1);
    assert_eq!(report.trials[2].state, "failed");
    assert!(report
        .output()
        .contains("completed 2 / planned 3 · failed 1"));
}

#[test]
fn occurrence_ratio_never_changes_the_fail_on_security_result() {
    use crate::capabilities::campaign::{
        BatchSecurityGateStatus, ScanBatchGateCounts, ScanBatchGateOutcome, ScanBatchGatePolicy,
    };

    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let store = gate_fixture_store(target.path());
    let finding = Finding::new_tool(
        "semgrep",
        "rule/cwe-78",
        "src/shell.rs",
        10,
        Some(10),
        Severity::High,
        "command injection, CWE-78",
    );
    store.insert_finding("run-trial-1-a1", &finding).unwrap();
    let sparse =
        derive_batch_occurrence_report_for_controller(target.path(), "batch-test", &store).unwrap();
    let mut repeated = sparse.clone();
    repeated.rows[0].seen = repeated.completed;
    let policy = ScanBatchGatePolicy {
        fail_on: Some(Severity::High),
        sarif: None,
    };
    let (sparse_binding, sparse_blocking) =
        derive_batch_gate_binding(&store, &sparse, policy.fail_on, None).unwrap();
    let (repeated_binding, repeated_blocking) =
        derive_batch_gate_binding(&store, &repeated, policy.fail_on, None).unwrap();

    assert_eq!(sparse_blocking, repeated_blocking);
    assert_eq!(
        sparse_binding.blocking_findings_sha256,
        repeated_binding.blocking_findings_sha256
    );
    let counts = |blocking_safe_fold_count| ScanBatchGateCounts {
        planned_trials: sparse.planned,
        completed_trials: sparse.completed,
        failed_trials: sparse.failed,
        pending_trials: sparse.pending,
        completed_run_ids: sparse.completed_run_ids(),
        blocking_safe_fold_count,
        sarif_written: false,
    };
    let sparse_gate = ScanBatchGateOutcome::new(
        "batch-test",
        &sparse.equivalence_key,
        &policy,
        counts(sparse_blocking),
        sparse_binding,
    );
    let repeated_gate = ScanBatchGateOutcome::new(
        "batch-test",
        &repeated.equivalence_key,
        &policy,
        counts(repeated_blocking),
        repeated_binding,
    );

    assert_eq!(sparse_gate.security_status, BatchSecurityGateStatus::Failed);
    assert_eq!(sparse_gate.security_status, repeated_gate.security_status);
    assert_eq!(
        sparse_gate.blocking_safe_fold_count,
        repeated_gate.blocking_safe_fold_count
    );
}

#[test]
fn safe_fold_keeps_file_fallback_source_signatures_separate() {
    let mut first = Finding::new_tool(
        "semgrep",
        "rule/cwe-78",
        "src/shell.rs",
        10,
        Some(10),
        Severity::High,
        "first shell sink, CWE-78",
    );
    let mut second = first.clone();
    first.identity_id = Some("fi_shared".to_string());
    second.identity_id = Some("fi_shared".to_string());
    first.identity_basis = Some(FindingIdentityBasis::FileFallback);
    second.identity_basis = Some(FindingIdentityBasis::FileFallback);
    first.source_signature = Some("sig:first".to_string());
    second.source_signature = Some("sig:second".to_string());

    assert_ne!(
        finding_projection_key(&first, IdentityFoldPolicy::Safe),
        finding_projection_key(&second, IdentityFoldPolicy::Safe)
    );
    assert_eq!(
        finding_projection_key(&first, IdentityFoldPolicy::Aggressive),
        finding_projection_key(&second, IdentityFoldPolicy::Aggressive)
    );
}

#[test]
fn safe_fold_requires_nonempty_file_fallback_evidence() {
    let mut first = file_fallback_finding("fp:first", Some("  "), Some(""));
    let mut second = file_fallback_finding("fp:second", None, Some(" \t "));

    assert_eq!(
        finding_projection_key(&first, IdentityFoldPolicy::Safe),
        "fingerprint:fp:first"
    );
    assert_eq!(
        finding_projection_key(&second, IdentityFoldPolicy::Safe),
        "fingerprint:fp:second"
    );

    first.source_signature = Some("  sig:same ".to_string());
    second.source_signature = Some("sig:same".to_string());
    assert_eq!(
        finding_projection_key(&first, IdentityFoldPolicy::Safe),
        finding_projection_key(&second, IdentityFoldPolicy::Safe)
    );

    first.source_signature = None;
    second.source_signature = None;
    first.dedup_key = Some(" bucket:same ".to_string());
    second.dedup_key = Some("bucket:same".to_string());
    assert_eq!(
        finding_projection_key(&first, IdentityFoldPolicy::Safe),
        finding_projection_key(&second, IdentityFoldPolicy::Safe)
    );
}

#[test]
fn attack_chains_never_use_identity_or_fallback_evidence() {
    let mut first = file_fallback_finding("chain:first", Some("sig:same"), Some("same"));
    let mut second = file_fallback_finding("chain:second", Some("sig:same"), Some("same"));
    first.tool = "chains".to_string();
    second.rule_id = "exploit-chain/fixture".to_string();

    assert_eq!(
        finding_projection_key(&first, IdentityFoldPolicy::Safe),
        "fingerprint:chain:first"
    );
    assert_eq!(
        finding_projection_key(&second, IdentityFoldPolicy::Aggressive),
        "fingerprint:chain:second"
    );
}

fn file_fallback_finding(
    fingerprint: &str,
    source_signature: Option<&str>,
    dedup_key: Option<&str>,
) -> Finding {
    let mut finding = Finding::new_tool(
        "semgrep",
        "rule/cwe-78",
        "src/shell.rs",
        10,
        Some(10),
        Severity::High,
        "shell sink, CWE-78",
    );
    finding.fingerprint = fingerprint.to_string();
    finding.identity_id = Some("fi_shared".to_string());
    finding.identity_basis = Some(FindingIdentityBasis::FileFallback);
    finding.source_signature = source_signature.map(str::to_string);
    finding.dedup_key = dedup_key.map(str::to_string);
    finding
}

#[test]
fn mixed_runtime_receipts_refuse_one_occurrence_ratio() {
    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let expected = planned_config_sha256(target.path());
    write_trial_receipt(target.path(), "run-trial-1-a1", &expected);
    write_trial_receipt(target.path(), "run-trial-1-a2", &expected);
    write_trial_receipt(target.path(), "run-trial-2-a1", "sha256:different");
    write_trial_receipt(target.path(), "run-trial-3-a1", &expected);
    write_trial_receipt(target.path(), "run-trial-3-a2", &expected);
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("mixed runtime/config receipt"));
}

#[test]
fn occurrence_report_requires_the_authenticated_equivalence_receipt() {
    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let path =
        crate::capabilities::campaign::campaign_dir(target.path(), "batch-test").join("plan.json");
    let mut plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    plan.as_object_mut().unwrap().remove("equivalence");
    std::fs::write(path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("equivalence"));
}

#[test]
fn prelaunch_trials_are_reported_without_inventing_attempt_receipts() {
    let target = tempfile::tempdir().unwrap();
    compile_batch_plan(
        target.path(),
        crate::capabilities::campaign::ScanBatchGatePolicy::default(),
    );
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let report = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap();

    assert_eq!((report.planned, report.completed), (3, 0));
    assert_eq!((report.failed, report.pending), (0, 3));
    assert!(report.rows.is_empty());
    assert!(report
        .trials
        .iter()
        .all(|trial| trial.state == "planned" && trial.attempt_run_ids.is_empty()));
}

#[test]
fn attemptless_pending_parked_and_prelaunch_failed_trials_remain_visible() {
    let target = tempfile::tempdir().unwrap();
    compile_batch_plan(
        target.path(),
        crate::capabilities::campaign::ScanBatchGatePolicy::default(),
    );
    write_batch_queue(
        target.path(),
        json!({"jobs": {
            "trial-001": {"state": "pending", "attempts": 0},
            "trial-002": {"state": "parked", "attempts": 0, "reason": "batch-equivalence-drift"},
            "trial-003": {"state": "failed", "attempts": 0, "reason": "prepare-failed"}
        }}),
    );
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let report = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap();

    assert_eq!((report.planned, report.completed), (3, 0));
    assert_eq!((report.failed, report.pending), (2, 1));
    assert!(report.all_attempt_run_ids().is_empty());
}

#[test]
fn completed_trial_cannot_claim_success_without_an_authenticated_attempt() {
    let target = tempfile::tempdir().unwrap();
    compile_batch_plan(
        target.path(),
        crate::capabilities::campaign::ScanBatchGatePolicy::default(),
    );
    write_batch_queue(
        target.path(),
        json!({"jobs": {
            "trial-001": {"state": "completed", "attempts": 0},
            "trial-002": {"state": "planned", "attempts": 0},
            "trial-003": {"state": "planned", "attempts": 0}
        }}),
    );
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("no authenticated attempt receipt"));
}

#[test]
fn attempt_counter_without_attempt_identity_fails_closed() {
    let target = tempfile::tempdir().unwrap();
    compile_batch_plan(
        target.path(),
        crate::capabilities::campaign::ScanBatchGatePolicy::default(),
    );
    write_batch_queue(
        target.path(),
        json!({"jobs": {
            "trial-001": {"state": "failed", "attempts": 1},
            "trial-002": {"state": "planned", "attempts": 0},
            "trial-003": {"state": "planned", "attempts": 0}
        }}),
    );
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("attempts without attempt run ids"));
}

#[test]
fn explicitly_abandoned_receiptless_attempt_remains_in_retry_history() {
    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let dir = crate::capabilities::campaign::campaign_dir(target.path(), "batch-test");
    let path = dir.join("queue.json");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    queue["jobs"]["trial-001"]["attemptRuns"][0]["outcome"] =
        json!(crate::capabilities::campaign::RECEIPTLESS_ATTEMPT_OUTCOME);
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
    let expected = planned_config_sha256(target.path());
    write_trial_receipt(target.path(), "run-trial-1-a2", &expected);
    write_trial_receipt(target.path(), "run-trial-2-a1", &expected);
    write_trial_receipt(target.path(), "run-trial-3-a1", &expected);
    write_trial_receipt(target.path(), "run-trial-3-a2", &expected);
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let report = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap();

    assert_eq!((report.completed, report.failed), (2, 1));
    assert!(report
        .trials
        .first()
        .unwrap()
        .attempt_run_ids
        .contains(&"run-trial-1-a1".to_string()));
}

#[test]
fn completed_trial_needs_one_non_abandoned_authenticated_attempt() {
    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let path = crate::capabilities::campaign::campaign_dir(target.path(), "batch-test")
        .join("queue.json");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for attempt in queue["jobs"]["trial-001"]["attemptRuns"]
        .as_array_mut()
        .unwrap()
    {
        attempt["outcome"] = json!(crate::capabilities::campaign::RECEIPTLESS_ATTEMPT_OUTCOME);
    }
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
    let expected = planned_config_sha256(target.path());
    for run_id in ["run-trial-2-a1", "run-trial-3-a1", "run-trial-3-a2"] {
        write_trial_receipt(target.path(), run_id, &expected);
    }
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("no authenticated attempt receipt"));
}

#[test]
fn non_abandoned_attempt_requires_child_consumption_equivalence_evidence() {
    let target = tempfile::tempdir().unwrap();
    seed_batch_documents(target.path());
    let expected = planned_config_sha256(target.path());
    for run_id in [
        "run-trial-1-a1",
        "run-trial-1-a2",
        "run-trial-2-a1",
        "run-trial-3-a1",
        "run-trial-3-a2",
    ] {
        write_trial_receipt(target.path(), run_id, &expected);
    }
    std::fs::remove_file(crate::run_artifacts::run_artifact_path(
        target.path(),
        "run-trial-2-a1",
        crate::capabilities::campaign::SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
    ))
    .unwrap();
    let store = FindingStore::open(target.path().join("findings.db")).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("lacks child-consumption equivalence evidence"),
        "{error}"
    );
}

#[test]
fn persisted_gate_refuses_terminal_state_drift() {
    let target = tempfile::tempdir().unwrap();
    let sarif = target.path().join("batch.sarif");
    let policy = gate_policy(sarif.clone());
    seed_batch_documents_with_policy(target.path(), policy.clone());
    let store = gate_fixture_store(target.path());
    std::fs::write(&sarif, b"current sarif").unwrap();
    persist_current_gate(target.path(), &store, &policy);
    let queue_path =
        crate::capabilities::campaign::campaign_dir(target.path(), "batch-test").join("queue.json");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&queue_path).unwrap()).unwrap();
    queue["jobs"]["trial-002"]["state"] = json!("failed");
    std::fs::write(queue_path, serde_json::to_vec(&queue).unwrap()).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("batch gate is stale"), "{error}");
}

#[test]
fn persisted_gate_refuses_finding_drift() {
    let target = tempfile::tempdir().unwrap();
    let sarif = target.path().join("batch.sarif");
    let policy = gate_policy(sarif.clone());
    seed_batch_documents_with_policy(target.path(), policy.clone());
    let store = gate_fixture_store(target.path());
    std::fs::write(&sarif, b"current sarif").unwrap();
    persist_current_gate(target.path(), &store, &policy);
    let finding = Finding::new_tool(
        "secret-scan",
        "fixture/high",
        "src/app.rs",
        1,
        Some(1),
        Severity::High,
        "new blocking finding",
    );
    store.insert_finding("run-trial-1-a2", &finding).unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("batch gate is stale"), "{error}");
}

#[test]
fn persisted_gate_refuses_final_sarif_drift() {
    let target = tempfile::tempdir().unwrap();
    let sarif = target.path().join("batch.sarif");
    let policy = gate_policy(sarif.clone());
    seed_batch_documents_with_policy(target.path(), policy.clone());
    let store = gate_fixture_store(target.path());
    std::fs::write(&sarif, b"current sarif").unwrap();
    persist_current_gate(target.path(), &store, &policy);
    std::fs::write(&sarif, b"changed sarif").unwrap();

    let error = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap_err();

    assert!(error.to_string().contains("batch gate is stale"), "{error}");
}

fn gate_policy(path: std::path::PathBuf) -> crate::capabilities::campaign::ScanBatchGatePolicy {
    crate::capabilities::campaign::ScanBatchGatePolicy {
        fail_on: Some(Severity::High),
        sarif: Some(path),
    }
}

fn gate_fixture_store(root: &Path) -> FindingStore {
    let expected = planned_config_sha256(root);
    for run_id in [
        "run-trial-1-a1",
        "run-trial-1-a2",
        "run-trial-2-a1",
        "run-trial-3-a1",
        "run-trial-3-a2",
    ] {
        write_trial_receipt(root, run_id, &expected);
    }
    let store = FindingStore::open(root.join("findings.db")).unwrap();
    for run_id in ["run-trial-1-a1", "run-trial-1-a2", "run-trial-2-a1"] {
        store.record_run_started(run_id, root, "completed").unwrap();
    }
    store
}

fn persist_current_gate(
    root: &Path,
    store: &FindingStore,
    policy: &crate::capabilities::campaign::ScanBatchGatePolicy,
) {
    use crate::capabilities::campaign::{ScanBatchGateCounts, ScanBatchGateOutcome};
    let report = derive_batch_occurrence_report_for_controller(root, "batch-test", store).unwrap();
    let (binding, blocking) =
        derive_batch_gate_binding(store, &report, policy.fail_on, policy.sarif.as_deref()).unwrap();
    let outcome = ScanBatchGateOutcome::new(
        "batch-test",
        &report.equivalence_key,
        policy,
        ScanBatchGateCounts {
            planned_trials: report.planned,
            completed_trials: report.completed,
            failed_trials: report.failed,
            pending_trials: report.pending,
            completed_run_ids: report.completed_run_ids(),
            blocking_safe_fold_count: blocking,
            sarif_written: true,
        },
        binding,
    );
    crate::capabilities::campaign::persist_batch_gate_outcome(root, &outcome).unwrap();
    derive_batch_occurrence_report(root, "batch-test", store).unwrap();
}

fn write_trial_receipt(root: &Path, run_id: &str, config_sha256: &str) {
    write_child_equivalence_receipt(root, run_id);
    let record = crate::run_artifacts::ToolRunRecord::new(root, run_id, "run", "sast:scan");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        None,
        Some(config_sha256.to_string()),
        Vec::new(),
    )
    .unwrap();
    crate::run_artifacts::try_record_tool_run_complete(
        record,
        &json!({"status": "completed", "data": {"engines": ["secret-scan"]}}),
    )
    .unwrap();
}

fn write_child_equivalence_receipt(root: &Path, run_id: &str) {
    let dir = crate::capabilities::campaign::campaign_dir(root, "batch-test");
    let plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("plan.json")).unwrap()).unwrap();
    let queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("queue.json")).unwrap()).unwrap();
    let job_id = queue["jobs"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, job)| {
            job["attemptRuns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|attempt| attempt["runId"] == run_id)
        })
        .map(|(job_id, _)| job_id)
        .unwrap();
    let input = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|job| job["jobId"] == job_id.as_str())
        .unwrap()["input"]
        .clone();
    crate::capabilities::campaign::verify_scan_batch_child_equivalence(
        root,
        run_id,
        &input,
        &crate::V2Config::default(),
        &crate::ModuleRegistry::with_v2_builtins(),
    )
    .unwrap();
}

fn planned_config_sha256(root: &Path) -> String {
    let path = crate::capabilities::campaign::campaign_dir(root, "batch-test").join("plan.json");
    let plan: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    plan.pointer("/equivalence/configSha256")
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_string()
}

fn seed_batch_documents(root: &Path) {
    seed_batch_documents_with_policy(
        root,
        crate::capabilities::campaign::ScanBatchGatePolicy::default(),
    );
}

fn seed_batch_documents_with_policy(
    root: &Path,
    gate_policy: crate::capabilities::campaign::ScanBatchGatePolicy,
) {
    compile_batch_plan(root, gate_policy);
    write_batch_queue(
        root,
        json!({
            "jobs": {
                "trial-001": {
                    "state": "completed", "attempts": 2, "runId": "run-trial-1-a2",
                    "attemptRuns": [
                        {"runId": "run-trial-1-a1"}, {"runId": "run-trial-1-a2"}
                    ]
                },
                "trial-002": {
                    "state": "completed", "attempts": 1, "runId": "run-trial-2-a1",
                    "attemptRuns": [{"runId": "run-trial-2-a1"}]
                },
                "trial-003": {
                    "state": "failed", "attempts": 2, "runId": "run-trial-3-a2",
                    "attemptRuns": [
                        {"runId": "run-trial-3-a1"}, {"runId": "run-trial-3-a2"}
                    ]
                }
            }
        }),
    );
}

fn compile_batch_plan(
    root: &Path,
    gate_policy: crate::capabilities::campaign::ScanBatchGatePolicy,
) {
    std::fs::write(root.join("source.rs"), "fn main() {}\n").unwrap();
    let registry = crate::ModuleRegistry::with_v2_builtins();
    crate::capabilities::campaign::compile_scan_batch_plan(
        crate::capabilities::campaign::ScanBatchPlanSpec {
            root,
            batch_id: Some("batch-test".to_string()),
            trials: 3,
            requested_workers: 1,
            gate_policy,
            prepared_input: json!({
                "triage": false, "identityFold": "safe",
                "taskMode": "manual", "tasks": ["secret-scan"]
            }),
            config: &crate::V2Config::default(),
            registry: &registry,
        },
    )
    .unwrap();
}

fn write_batch_queue(root: &Path, queue: serde_json::Value) {
    let path = crate::capabilities::campaign::campaign_dir(root, "batch-test").join("queue.json");
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
}

#[test]
fn a_plan_row_without_a_job_id_reports_unknown_rather_than_planned() {
    // A trial nobody can bind to queue state must not read as "not started
    // yet": that would let an unreadable trial count toward a clean batch.
    let trials = super::load::trial_reports(
        &json!({"jobs": [{"trial": 1}, {"trial": 2, "jobId": "trial-002"}]}),
        Some(&json!({"jobs": {"trial-002": {"state": "completed"}}})),
    );

    assert_eq!(trials[0].state, "unknown");
    assert!(trials[0].job_id.is_empty());
    assert_eq!(trials[1].state, "completed");
}

#[test]
fn a_planned_trial_is_still_reported_as_planned_when_the_queue_has_no_entry() {
    let trials = super::load::trial_reports(
        &json!({"jobs": [{"trial": 1, "jobId": "trial-001"}]}),
        Some(&json!({"jobs": {}})),
    );

    assert_eq!(trials[0].state, "planned");
}
