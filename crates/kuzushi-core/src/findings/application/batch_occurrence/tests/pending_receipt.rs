use super::*;

const CURRENT: &str = "run-trial-3-a3";

fn starting_fixture(root: &Path) -> FindingStore {
    seed_batch_documents(root);
    let expected = planned_config_sha256(root);
    for run in [
        "run-trial-1-a1",
        "run-trial-1-a2",
        "run-trial-2-a1",
        "run-trial-3-a1",
        "run-trial-3-a2",
    ] {
        write_trial_receipt(root, run, &expected);
    }
    let workspace = crate::WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    set_queue_state(root, "running");
    store
}

fn set_queue_state(root: &Path, state: &str) {
    let path = crate::capabilities::campaign::campaign_queue_path(root, "batch-test");
    let mut queue: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    queue["jobs"]["trial-003"] = json!({
        "state":state,"attempts":3,"runId":CURRENT,
        "attemptRuns":[{"runId":"run-trial-3-a1"},{"runId":"run-trial-3-a2"},{"runId":CURRENT}]
    });
    std::fs::write(path, queue.to_string()).unwrap();
}

fn start_current(root: &Path) {
    let record = crate::run_artifacts::ToolRunRecord::new(root, CURRENT, "run", "sast:scan");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        None,
        Some(planned_config_sha256(root)),
        vec![],
    )
    .unwrap();
}

fn read(root: &Path, store: &FindingStore) -> Result<BatchOccurrenceReport> {
    derive_batch_occurrence_report_for_controller(root, "batch-test", store)
}

#[test]
fn queued_current_attempt_waits_for_metadata_without_authenticating_a_report() {
    let root = tempfile::tempdir().unwrap();
    let store = starting_fixture(root.path());
    let error = read(root.path(), &store).unwrap_err();
    assert!(error.is::<BatchReceiptPending>(), "{error:#}");
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let filter = crate::FindingListFilter {
        batch_id: Some("batch-test".into()),
        ..Default::default()
    };
    let error = crate::findings::read_finding_page_snapshot(
        &store,
        &workspace,
        &filter,
        IdentityFoldPolicy::Safe,
        &crate::findings::FindingPageRequest::default(),
    )
    .unwrap_err();
    assert!(error.is::<BatchReceiptPending>(), "{error:#}");
}

#[test]
fn started_current_attempt_waits_for_consumption_receipt_then_reads_pending_work() {
    let root = tempfile::tempdir().unwrap();
    let store = starting_fixture(root.path());
    start_current(root.path());
    let error = read(root.path(), &store).unwrap_err();
    assert!(error.is::<BatchReceiptPending>(), "{error:#}");
    write_child_equivalence_receipt(root.path(), CURRENT);
    let report = read(root.path(), &store).unwrap();
    assert_eq!((report.completed, report.pending), (2, 1));
    assert!(report.rows.is_empty());
}

#[test]
fn terminal_or_parked_queue_states_cannot_hide_a_missing_receipt_as_pending() {
    for state in ["completed", "failed", "parked", "unknown"] {
        let root = tempfile::tempdir().unwrap();
        let store = starting_fixture(root.path());
        start_current(root.path());
        set_queue_state(root.path(), state);
        let error = read(root.path(), &store).unwrap_err();
        assert!(!error.is::<BatchReceiptPending>(), "{state}: {error:#}");
    }
}

#[test]
fn malformed_and_nonfile_child_receipts_are_hard_errors_during_startup() {
    for nonfile in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let store = starting_fixture(root.path());
        start_current(root.path());
        let path = root
            .path()
            .join(".kuzushi/v3/runs")
            .join(CURRENT)
            .join("batch-equivalence.json");
        if nonfile {
            std::fs::create_dir(path).unwrap();
        } else {
            std::fs::write(path, "{ malformed").unwrap();
        }
        let error = read(root.path(), &store).unwrap_err();
        assert!(!error.is::<BatchReceiptPending>(), "{error:#}");
    }
}

#[test]
fn a_running_retry_cannot_hide_missing_historical_evidence() {
    let root = tempfile::tempdir().unwrap();
    let store = starting_fixture(root.path());
    std::fs::remove_file(root.path().join(".kuzushi/v3/runs/run-trial-3-a1/run.json")).unwrap();
    let error = read(root.path(), &store).unwrap_err();
    assert!(!error.is::<BatchReceiptPending>(), "{error:#}");
    assert!(error.to_string().contains("run-trial-3-a1"));
}

#[test]
fn a_missing_child_receipt_cannot_hide_a_mixed_runtime_config() {
    let root = tempfile::tempdir().unwrap();
    let store = starting_fixture(root.path());
    start_current(root.path());
    let path = root
        .path()
        .join(".kuzushi/v3/runs")
        .join(CURRENT)
        .join("run.json");
    let mut summary: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    summary["configHash"] = json!("sha256:wrong-config");
    std::fs::write(path, summary.to_string()).unwrap();
    let error = read(root.path(), &store).unwrap_err();
    assert!(!error.is::<BatchReceiptPending>(), "{error:#}");
    assert!(
        error.to_string().contains("mixed runtime/config"),
        "{error:#}"
    );
}

#[test]
fn an_unrelated_missing_artifact_cannot_turn_a_real_failure_into_pending() {
    let trial = BatchTrialReport {
        trial: 3,
        job_id: "trial-003".into(),
        state: "running".into(),
        attempts: 1,
        run_id: Some(CURRENT.into()),
        attempt_run_ids: vec![CURRENT.into()],
        finding_run_ids: vec![],
        failure_reason: None,
    };
    for path in [
        "owned/run-trial-3-a3/result.json",
        "owned/another-run/run.json",
    ] {
        let error = crate::run_artifacts::RunArtifactRead::<String>::Missing { path: path.into() }
            .require("Owned artifact")
            .unwrap_err();
        let classified = super::super::pending_receipt::current_attempt_error(
            &trial, CURRENT, "run.json", error,
        );
        assert!(!classified.is::<BatchReceiptPending>(), "{classified:#}");
    }
}

#[test]
fn a_terminal_summary_cannot_wait_for_a_missing_child_receipt() {
    for status in ["failed", "completed"] {
        let root = tempfile::tempdir().unwrap();
        let store = starting_fixture(root.path());
        start_current(root.path());
        let record =
            crate::run_artifacts::ToolRunRecord::new(root.path(), CURRENT, "run", "sast:scan");
        crate::run_artifacts::try_record_tool_run_complete(record, &json!({"status":status}))
            .unwrap();
        let error = read(root.path(), &store).unwrap_err();
        assert!(!error.is::<BatchReceiptPending>(), "{status}: {error:#}");
        assert!(error.to_string().contains("child-consumption"), "{error:#}");
    }
}
