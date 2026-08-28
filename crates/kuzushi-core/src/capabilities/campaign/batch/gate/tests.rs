use super::*;

fn counts(blocking: usize) -> ScanBatchGateCounts {
    ScanBatchGateCounts {
        planned_trials: 3,
        completed_trials: 2,
        failed_trials: 1,
        pending_trials: 0,
        completed_run_ids: vec!["run-a".to_string(), "run-b".to_string()],
        blocking_safe_fold_count: blocking,
        sarif_written: false,
    }
}

fn complete_counts(blocking: usize) -> ScanBatchGateCounts {
    ScanBatchGateCounts {
        completed_trials: 3,
        failed_trials: 0,
        ..counts(blocking)
    }
}

fn binding(sarif: bool) -> ScanBatchGateBinding {
    ScanBatchGateBinding {
        logical_terminal_state_sha256: "sha256:state".to_string(),
        blocking_findings_sha256: "sha256:findings".to_string(),
        sarif_path: sarif.then(|| PathBuf::from("/tmp/batch.sarif")),
        sarif_sha256: sarif.then(|| "sha256:sarif".to_string()),
    }
}

#[test]
fn gate_outcome_distinguishes_disabled_passed_and_failed() {
    let disabled = ScanBatchGateOutcome::new(
        "batch",
        "eq",
        &ScanBatchGatePolicy::default(),
        complete_counts(4),
        binding(false),
    );
    assert_eq!(disabled.status, BatchGateStatus::Disabled);
    let policy = ScanBatchGatePolicy {
        fail_on: Some(Severity::High),
        sarif: Some(PathBuf::from("batch.sarif")),
    };
    assert_eq!(
        ScanBatchGateOutcome::new("batch", "eq", &policy, complete_counts(0), binding(false))
            .status,
        BatchGateStatus::Passed,
    );
    assert_eq!(
        ScanBatchGateOutcome::new("batch", "eq", &policy, complete_counts(2), binding(false))
            .status,
        BatchGateStatus::Failed
    );
    let incomplete = ScanBatchGateOutcome::new("batch", "eq", &policy, counts(0), binding(false));
    assert_eq!(incomplete.status, BatchGateStatus::Incomplete);
    assert_eq!(
        incomplete.operational_status,
        BatchOperationalStatus::Incomplete
    );
    assert_eq!(incomplete.security_status, BatchSecurityGateStatus::Passed);
}

#[test]
fn gate_result_is_published_atomically_beside_the_plan() {
    let root = tempfile::tempdir().unwrap();
    let outcome = ScanBatchGateOutcome::new(
        "batch-gate",
        "eq",
        &ScanBatchGatePolicy::default(),
        complete_counts(0),
        binding(false),
    );
    let path = persist_batch_gate_outcome(root.path(), &outcome).unwrap();
    let stored: ScanBatchGateOutcome =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(stored.batch_id, "batch-gate");
    assert_eq!(stored.status, BatchGateStatus::Disabled);
}

#[test]
fn annotated_batch_sarif_is_atomically_replaced_and_digested() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("batch.sarif");
    std::fs::write(&path, b"stale").unwrap();
    let document = serde_json::json!({"version": "2.1.0", "runs": []});

    let digest = persist_batch_sarif_document(&path, &document).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(digest, crate::run_lifecycle::sha256_content_digest(&bytes));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        document
    );
    assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")
    }));
}
