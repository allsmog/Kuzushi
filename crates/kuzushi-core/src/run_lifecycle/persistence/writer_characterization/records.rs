use crate::run_lifecycle::{
    DiagnosticLevel, OperationFingerprint, RunCallId, RunId, RunItemEnvelopeV1, RunItemId,
    RunItemRecord, RunItemSource, RunItemStatus, RunItemV1, SafeText, WorkflowContinuation,
    RUN_ITEM_REDACTION_POLICY_VERSION,
};
use crate::runtime::RuntimeCostReport;

pub(super) fn diagnostic(message: &str) -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible(message),
        },
    )
}

pub(super) fn progress(item_id: RunItemId, index: u64) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Runtime,
        RunItemV1::SafeReasoningSummary {
            text: SafeText::operator_visible(format!("progress-{index}")),
            redaction_policy_version: RUN_ITEM_REDACTION_POLICY_VERSION,
        },
    )
}

pub(super) fn terminal_record() -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Completed,
            summary: SafeText::operator_visible("complete"),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("done"),
            },
        },
    )
}

pub(super) fn tool_call_finished_record() -> RunItemRecord {
    tool_call_finished_record_for(RunCallId::new(), RunItemId::new())
}

pub(super) fn tool_call_requested_record(call_id: RunCallId, item_id: RunItemId) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("security:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"saturated-post-exec"),
            safe_option_names: Vec::new(),
        },
    )
    .with_call(call_id)
}

pub(super) fn tool_call_started_record(call_id: RunCallId, item_id: RunItemId) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallStarted {
            tool_name: SafeText::operator_visible("security:scan"),
            runtime: None,
            model: None,
        },
    )
    .with_call(call_id)
}

pub(super) fn tool_call_finished_record_for(
    call_id: RunCallId,
    item_id: RunItemId,
) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Partial,
            cost: RuntimeCostReport::UNAVAILABLE,
            result_artifact: None,
            preview: vec![SafeText::preview_line(
                "settlement incomplete; do not retry automatically",
            )],
            warning_count: 0,
            error_count: 1,
        },
    )
    .with_call(call_id)
}

pub(super) fn partial_terminal_record(run_id: &str) -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Partial,
            summary: SafeText::operator_visible("result settlement incomplete after execution"),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::InspectRun {
                run_id: RunId::parse(run_id).unwrap(),
                reason: SafeText::operator_visible(
                    "side effects may have occurred; do not retry automatically",
                ),
            },
        },
    )
}

pub(super) fn envelope(record: RunItemRecord) -> RunItemEnvelopeV1 {
    RunItemEnvelopeV1::from_record(
        1,
        RunId::parse("run-writer-characterization").unwrap(),
        record,
        None,
    )
    .unwrap()
}

pub(super) fn omitted_progress(items: &[RunItemEnvelopeV1]) -> u64 {
    items
        .iter()
        .filter_map(|item| match item.item {
            RunItemV1::ProgressTruncated { omitted_count, .. } => Some(omitted_count),
            _ => None,
        })
        .sum()
}

pub(super) fn diagnostic_count(items: &[RunItemEnvelopeV1]) -> usize {
    items
        .iter()
        .filter(|item| matches!(item.item, RunItemV1::DiagnosticNotice { .. }))
        .count()
}

pub(super) fn progress_count(items: &[RunItemEnvelopeV1]) -> u64 {
    items
        .iter()
        .filter(|item| matches!(item.item, RunItemV1::SafeReasoningSummary { .. }))
        .count() as u64
}
