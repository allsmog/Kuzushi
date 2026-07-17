use super::*;
use crate::run_lifecycle::{
    DiagnosticLevel, PersistenceFailureStage, RunItemId, RunItemRecord, RunItemSource,
    RunItemStatus, RunItemV1, SafeText, WorkflowContinuation, MAX_RUN_ITEM_STREAM_BYTES,
    RUN_ITEM_CRITICAL_RESERVE_BYTES,
};
use crate::runtime::RuntimeCostReport;

#[test]
fn writer_reply_preserves_structured_fault_for_callers() {
    let fault = RunItemWriterFault {
        stage: PersistenceFailureStage::Sync,
        last_durable_seq: 7,
        detail: SafeText::operator_visible("sync failed"),
        execution_may_have_occurred: true,
    };

    let error = receive_result::<()>(Ok(Err(fault.clone())), "test write").unwrap_err();

    assert_eq!(error.downcast_ref::<RunItemWriterFault>(), Some(&fault));
}

#[test]
fn execution_annotation_is_monotonic_and_forbids_automatic_retry() {
    let fault = RunItemWriterFault {
        stage: PersistenceFailureStage::Sync,
        last_durable_seq: 2,
        detail: SafeText::operator_visible("sync failed"),
        execution_may_have_occurred: false,
    };

    let preflight = fault.clone().annotate_execution(false);
    let post_execution = fault.annotate_execution(true);

    assert!(!preflight.execution_may_have_occurred);
    assert!(!preflight.detail.as_str().contains("do not retry"));
    assert!(post_execution.execution_may_have_occurred);
    assert!(post_execution
        .detail
        .as_str()
        .contains("do not retry automatically"));
    assert!(
        post_execution
            .annotate_execution(false)
            .execution_may_have_occurred
    );
}

#[test]
fn reserve_recovery_allows_only_partial_or_failed_inspection_items() {
    for status in [RunItemStatus::Completed, RunItemStatus::Skipped] {
        assert!(inspection_records(status)
            .iter()
            .all(|record| !writer_worker::reserve_recovery_eligible_record(record)));
    }
    for status in [RunItemStatus::Partial, RunItemStatus::Failed] {
        assert!(inspection_records(status)
            .iter()
            .all(writer_worker::reserve_recovery_eligible_record));
    }
}

#[test]
fn sticky_budget_failure_refuses_completed_terminal_recovery() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("completed-reserve-recovery");
    let accounted = MAX_RUN_ITEM_STREAM_BYTES - RUN_ITEM_CRITICAL_RESERVE_BYTES;
    let writer = RunItemWriter::open_with_accounted_bytes_for_test(
        target.path(),
        &run_id,
        accounted,
    )
    .unwrap();
    assert!(writer.emit_and_flush(diagnostic()).is_err());
    let terminal = inspection_records(RunItemStatus::Completed).pop().unwrap();
    assert!(writer.emit_and_flush(terminal).is_err());
    assert!(writer.shutdown().is_err());
}

fn inspection_records(status: RunItemStatus) -> Vec<RunItemRecord> {
    vec![
        item(RunItemV1::PlanUpdated {
            revision: 1,
            title: SafeText::operator_visible("plan"),
            status,
            task_ids: Vec::new(),
        }),
        item(RunItemV1::TaskUpdated {
            title: SafeText::operator_visible("task"),
            status,
            detail: None,
        }),
        item(RunItemV1::ToolCallFinished {
            status,
            cost: RuntimeCostReport::UNAVAILABLE,
            result_artifact: None,
            preview: Vec::new(),
            warning_count: 0,
            error_count: u64::from(status == RunItemStatus::Failed),
        }),
        item(RunItemV1::TerminalOutcome {
            status,
            summary: SafeText::operator_visible("settlement"),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("test"),
            },
        }),
    ]
}

fn diagnostic() -> RunItemRecord {
    item(RunItemV1::DiagnosticNotice {
        level: DiagnosticLevel::Info,
        message: SafeText::operator_visible("ordinary item after saturation"),
    })
}

fn item(value: RunItemV1) -> RunItemRecord {
    RunItemRecord::new(RunItemId::new(), RunItemSource::Persistence, value)
}
