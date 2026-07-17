use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed_with_v2, append_phase_attempt_disposition,
    PhaseAttemptCompleted, PhaseAttemptDisposition, PhaseAttemptDispositionRecorded,
    PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use kuzushi_core::{WorkflowPhase, WorkspaceTarget};
use serde_json::{Map, Value};
use std::path::Path;

pub(crate) fn with_indexed_snapshot(target: &Path, mut output: Value) -> Value {
    let workspace = WorkspaceTarget::new(target).expect("test workspace");
    let indexed = kuzushi_core::incremental_index::index_workspace_snapshot(&workspace)
        .expect("indexed test workspace");
    let snapshot = snapshot_object(&mut output);
    snapshot.insert(
        "snapshotHash".to_string(),
        Value::String(indexed.snapshot_hash),
    );
    snapshot.insert("treeHash".to_string(), Value::String(indexed.tree_hash));
    output
}

pub(crate) fn record_indexed_run(target: &Path, run_id: &str, tool: &str, output: Value) {
    record_indexed_run_with_input(target, run_id, tool, Value::Object(Map::new()), output);
}

pub(crate) fn record_indexed_run_with_input(
    target: &Path,
    run_id: &str,
    tool: &str,
    input: Value,
    output: Value,
) {
    let output = with_indexed_snapshot(target, output);
    let record = kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "tool", tool);
    kuzushi_core::run_artifacts::record_tool_run_started(record, &input);
    let observation = kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, run_id)
        .expect("test run observation")
        .start_root_task("Execute deterministic test run")
        .expect("test semantic task");
    observation
        .task_handle()
        .expect("test task handle")
        .update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)
        .expect("running test task");
    let call =
        kuzushi_core::ApplicationToolCall::start(observation.clone(), tool, &input, None, None)
            .expect("test tool call");
    let completion = call.completion_from_result(&Ok(output.clone()));
    kuzushi_core::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &output,
        &observation,
        completion,
    )
    .expect("settled test run");
}

pub(crate) fn append_typed_attempt(
    target: &Path,
    phase: WorkflowPhase,
    run_id: &str,
    outcome: PhaseAttemptOutcome,
) -> PhaseAttemptCompleted {
    let completed = PhaseAttemptCompleted::new(
        phase,
        vec![run_id.to_string()],
        PhaseTargetSnapshot::capture(target),
        outcome,
    )
    .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string());
    append_phase_attempt_completed_with_v2(target, completed.clone()).expect("typed phase attempt");
    completed
}

pub(crate) fn select_typed_attempt(target: &Path, completed: &PhaseAttemptCompleted) {
    append_phase_attempt_disposition(
        target,
        PhaseAttemptDispositionRecorded::new(
            completed.attempt_id.clone(),
            PhaseAttemptDisposition::Selected {
                acknowledged_partial: completed.outcome == PhaseAttemptOutcome::Partial,
            },
        ),
    )
    .expect("typed phase disposition");
}

fn snapshot_object(output: &mut Value) -> &mut Map<String, Value> {
    let root = output.as_object_mut().expect("test result object");
    let data = root
        .entry("data")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("test result data object");
    data.entry("snapshot")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("test result snapshot object")
}
