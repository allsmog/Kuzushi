use super::records::{
    diagnostic, partial_terminal_record, tool_call_finished_record_for, tool_call_requested_record,
    tool_call_started_record,
};
use crate::run_lifecycle::{
    read_run_items, ProjectionHealth, RunCallId, RunItemId, RunItemStatus, RunItemWriter,
    RunItemWriterFault, RunProjection, WorkflowContinuation, MAX_RUN_ITEM_STREAM_BYTES,
    RUN_ITEM_CRITICAL_RESERVE_BYTES,
};

pub(super) struct SaturatedPostExecutionOutcome {
    call_id: RunCallId,
    fault: RunItemWriterFault,
    read_health: ProjectionHealth,
    projection: RunProjection,
    shutdown_failed: bool,
}

pub(super) fn exercise_saturated_post_execution() -> SaturatedPostExecutionOutcome {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("saturated-post-exec");
    let (call_id, call_item_id) = create_started_call(target.path(), &run_id);
    let (fault, shutdown_failed) =
        settle_saturated_call(target.path(), &run_id, call_id, call_item_id);
    let read_health = read_run_items(target.path(), &run_id)
        .unwrap()
        .unwrap()
        .health;
    let projection = crate::run_lifecycle::load_run_projection(target.path(), &run_id)
        .unwrap()
        .projection;
    SaturatedPostExecutionOutcome {
        call_id,
        fault,
        read_health,
        projection,
        shutdown_failed,
    }
}

fn create_started_call(target: &std::path::Path, run_id: &str) -> (RunCallId, RunItemId) {
    let call_id = RunCallId::new();
    let call_item_id = RunItemId::new();
    let writer = RunItemWriter::open(target, run_id, None).unwrap();
    writer
        .emit_and_flush(tool_call_requested_record(call_id, call_item_id))
        .unwrap();
    writer
        .emit_and_flush(tool_call_started_record(call_id, call_item_id))
        .unwrap();
    writer.shutdown().unwrap();
    (call_id, call_item_id)
}

fn settle_saturated_call(
    target: &std::path::Path,
    run_id: &str,
    call_id: RunCallId,
    call_item_id: RunItemId,
) -> (RunItemWriterFault, bool) {
    let writer = RunItemWriter::open_with_accounted_bytes_for_test(
        target,
        run_id,
        MAX_RUN_ITEM_STREAM_BYTES - RUN_ITEM_CRITICAL_RESERVE_BYTES,
    )
    .unwrap();
    let fault = writer
        .emit_and_flush(diagnostic("ordinary item after saturation"))
        .unwrap_err()
        .downcast_ref::<RunItemWriterFault>()
        .unwrap()
        .clone();
    writer
        .emit_and_flush(tool_call_finished_record_for(call_id, call_item_id))
        .unwrap();
    writer
        .emit_and_flush(partial_terminal_record(run_id))
        .unwrap();
    (fault, writer.shutdown().is_err())
}

pub(super) fn assert_saturated_outcome(outcome: &SaturatedPostExecutionOutcome) {
    assert!(!outcome.fault.execution_may_have_occurred);
    assert!(outcome.shutdown_failed);
    assert_eq!(outcome.read_health, ProjectionHealth::Healthy);
    let call = outcome.projection.calls.get(&outcome.call_id).unwrap();
    assert_eq!(call.status, RunItemStatus::Partial);
    assert!(call.result_artifact.is_none());
    assert!(call
        .preview
        .iter()
        .any(|line| line.as_str().contains("do not retry automatically")));
    assert!(matches!(
        outcome.projection.terminal.as_ref(),
        Some(crate::run_lifecycle::TerminalProjection {
            status: RunItemStatus::Partial,
            continuation: WorkflowContinuation::InspectRun { .. },
            ..
        })
    ));
}
