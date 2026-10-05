use super::*;

#[test]
fn checkpoint_health_is_separate_from_successful_execution_at_shared_boundary() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join(".kuzushi")).unwrap();
    let store =
        crate::run_artifacts::StageCheckpointStore::discover(temp.path(), &[3; 32]).unwrap();
    let handle = crate::run_artifacts::StageCheckpointHandle::open(
        store,
        temp.path(),
        "run-health",
        "demo:staged",
    );
    handle.mark_current(&"x".repeat(crate::checkpoint_limits::MAX_RECORD_BYTES));
    let mut output = Ok(serde_json::json!({"status":"completed", "data":{"kept":42}}));
    attach_resume_health(&mut output, Some(&handle));
    let value = output.unwrap();
    assert_eq!(value["status"], "completed");
    assert_eq!(value["data"]["kept"], 42);
    assert_eq!(value["resumeHealth"]["degraded"], true);
    assert_eq!(value["resumeHealth"]["retryOnNextDispatch"], true);
}
