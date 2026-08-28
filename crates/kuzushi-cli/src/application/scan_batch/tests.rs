use super::*;

fn request(trials: usize) -> ScanBatchRequest {
    ScanBatchRequest {
        target: PathBuf::from("target"),
        mode: None,
        tasks: Vec::new(),
        triage: None,
        json: false,
        ci: false,
        budget: None,
        scope: ScanScopeArgs::default(),
        since: None,
        include_worktree: false,
        gate: ScanGatePolicy::default(),
        trials,
        workers: 1,
    }
}

#[test]
fn sequential_batch_bounds_logical_trials_before_preparation() {
    assert!(validate_batch_request(&request(1)).is_err());
    assert!(validate_batch_request(&request(2)).is_ok());
    assert!(validate_batch_request(&request(MAX_SCAN_BATCH_TRIALS + 1)).is_err());
}

#[test]
fn batch_cli_refuses_per_trial_triage() {
    let mut request = request(2);
    request.triage = Some(true);

    let error = validate_batch_request(&request).unwrap_err().to_string();

    assert!(error.contains("discovery-only"), "{error}");
}

#[test]
fn operational_failure_precedes_a_security_gate_failure() {
    assert_eq!(
        batch_completion_status(true, false, true),
        BatchCompletionStatus::OperationalFailure
    );
    assert_eq!(
        batch_completion_status(false, false, true),
        BatchCompletionStatus::SecurityGateFailure
    );
    assert_eq!(
        batch_completion_status(false, true, false),
        BatchCompletionStatus::OperationalFailure
    );
}

#[test]
fn all_parked_drift_still_publishes_zero_completed_gate_and_sarif() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("source.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let sarif_path = target.path().join("batch.sarif");
    let gate = ScanGatePolicy {
        fail_on: None,
        sarif: Some(sarif_path.clone()),
    };
    compile_all_parked_batch(target.path(), &gate);
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();

    let error = finish_batch_controller(
        &workspace,
        &store,
        "batch-all-parked",
        &gate,
        false,
        false,
        Err(anyhow::anyhow!("batch equivalence drift")),
    )
    .unwrap_err();

    assert!(error.to_string().contains("batch equivalence drift"));
    assert_all_parked_gate(target.path());
    assert_all_parked_sarif(&sarif_path);
}

fn compile_all_parked_batch(target: &std::path::Path, gate: &ScanGatePolicy) {
    let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root: target,
        batch_id: Some("batch-all-parked".to_string()),
        trials: 3,
        requested_workers: 1,
        gate_policy: ScanBatchGatePolicy {
            fail_on: gate.fail_on,
            sarif: gate.sarif.clone(),
        },
        prepared_input: serde_json::json!({
            "triage": false,
            "identityFold": "safe",
            "taskMode": "manual",
            "tasks": ["secret-scan"]
        }),
        config: &kuzushi_core::V2Config::default(),
        registry: &registry,
    })
    .unwrap();
    let path = kuzushi_core::capabilities::campaign::campaign_dir(target, "batch-all-parked")
        .join("queue.json");
    let queue = serde_json::json!({"jobs": {
        "trial-001": parked_drift_job(),
        "trial-002": parked_drift_job(),
        "trial-003": parked_drift_job()
    }});
    std::fs::write(path, serde_json::to_vec(&queue).unwrap()).unwrap();
}

fn parked_drift_job() -> serde_json::Value {
    serde_json::json!({
        "state": "parked",
        "attempts": 0,
        "reason": "batch-equivalence-drift"
    })
}

fn assert_all_parked_gate(target: &std::path::Path) {
    let path = kuzushi_core::capabilities::campaign::campaign_dir(target, "batch-all-parked")
        .join("gate.json");
    let gate: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(gate["status"], "incomplete");
    assert_eq!(gate["plannedTrials"], 3);
    assert_eq!(gate["completedTrials"], 0);
    assert_eq!(gate["failedTrials"], 3);
    assert_eq!(gate["pendingTrials"], 0);
    assert_eq!(gate["sarifWritten"], true);
}

fn assert_all_parked_sarif(path: &std::path::Path) {
    let sarif: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        sarif.pointer("/properties/kuzushiBatch/trialsPlanned"),
        Some(&serde_json::json!(3))
    );
    assert_eq!(
        sarif.pointer("/properties/kuzushiBatch/trialsCompleted"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        sarif.pointer("/properties/kuzushiBatch/trialsFailed"),
        Some(&serde_json::json!(3))
    );
    assert_eq!(
        sarif.pointer("/properties/kuzushiBatch/rawAttemptRunIds"),
        Some(&serde_json::json!([]))
    );
    assert_eq!(
        sarif.pointer("/runs/0/results"),
        Some(&serde_json::json!([]))
    );
}
