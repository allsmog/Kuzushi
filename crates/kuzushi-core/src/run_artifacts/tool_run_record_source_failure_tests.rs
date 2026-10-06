use super::*;
use crate::run_lifecycle::RunItemStatus;
use crate::workflow_attempts::referenced_run_content_identity;

#[test]
fn failed_and_canceled_settlements_keep_authenticated_source_evidence() {
    for canceled in [false, true] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("lib.rs"), "fn before() {}\n").unwrap();
        let run_id = "source-bound-failure";
        settle_failure(root.path(), run_id, canceled);
        let expected_status = if canceled { "canceled" } else { "failed" };
        assert_eq!(
            load_run_summary(root.path(), run_id).unwrap().status,
            expected_status
        );
        let identity = referenced_run_content_identity(root.path(), &[run_id.to_string()]);
        assert!(identity.permits_cross_attempt_reuse(), "{identity:?}");
        let output: Value = serde_json::from_str(
            &std::fs::read_to_string(run_artifact_path(root.path(), run_id, "result.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(output["status"], expected_status);
        assert_eq!(
            output["data"]["treeHash"],
            crate::incremental_index::current_workspace_tree_hash(root.path()).unwrap()
        );
        assert_source_drift_and_tampering(root.path(), run_id, &output, identity);
    }
}

fn settle_failure(root: &Path, run_id: &str, canceled: bool) {
    let record = ToolRunRecord::new(root, run_id, "scan", "sast:scan");
    try_record_tool_run_started_with_reproducibility(record, &json!({}), None, None, Vec::new())
        .unwrap();
    let observation = crate::run_lifecycle::RunObservationHandle::jsonl(root, run_id)
        .unwrap()
        .start_root_task("Inspect source")
        .unwrap();
    observation
        .task_handle()
        .unwrap()
        .update_and_flush(RunItemStatus::Running, None)
        .unwrap();
    let call = crate::modules::ApplicationToolCall::start(
        observation.clone(),
        "sast:scan",
        &json!({}),
        None,
        None,
    )
    .unwrap();
    let result = source_bound_failure(root);
    let error = result.as_ref().unwrap_err().to_string();
    let completion = call.completion_from_result(&result);
    if canceled {
        try_record_tool_run_canceled_settled(record, &error, &observation, completion).unwrap();
    } else {
        try_record_tool_run_failed_settled(record, &error, &observation, completion).unwrap();
    }
}

fn source_bound_failure(root: &Path) -> Result<Value> {
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    crate::workspace::source_snapshot::run_source_bound_tool(&ctx, "sast:scan", root, || {
        anyhow::bail!("allowance refused before provider request")
    })
}

fn assert_source_drift_and_tampering(
    root: &Path,
    run_id: &str,
    output: &Value,
    identity: crate::workflow_attempts::TargetContentIdentity,
) {
    // A changed file does not rewrite the receipt into the new source identity.
    std::fs::write(root.join("lib.rs"), "fn changed() {}\n").unwrap();
    assert_ne!(
        output["data"]["treeHash"],
        crate::incremental_index::current_workspace_tree_hash(root).unwrap()
    );
    assert_eq!(
        referenced_run_content_identity(root, &[run_id.to_string()]),
        identity
    );
    std::fs::write(run_artifact_path(root, run_id, "result.json"), "{}").unwrap();
    assert!(
        !referenced_run_content_identity(root, &[run_id.to_string()]).permits_cross_attempt_reuse()
    );
}
