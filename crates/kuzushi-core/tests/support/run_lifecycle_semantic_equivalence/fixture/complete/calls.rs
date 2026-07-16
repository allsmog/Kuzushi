//! Tool and model call records for the complete fixture.

use super::super::*;
use kuzushi_core::run_lifecycle::{
    ArtifactReference, ModelUsage, OperationFingerprint, RUN_ITEM_REDACTION_POLICY_VERSION,
};

pub(super) fn outer_start_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![outer_requested(ids), outer_started(ids)]
}

fn outer_requested(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallRequested {
            tool_name: text("verification:verify"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"fixture-tool-input"),
            safe_option_names: vec![text("findingId")],
        },
    )
    .with_task(ids.task)
    .with_call(ids.tool_call)
}

fn outer_started(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallStarted {
            tool_name: text("verification:verify"),
            runtime: Some(text("agent")),
            model: Some(text("anthropic:claude-fixture")),
        },
    )
    .with_task(ids.task)
    .with_call(ids.tool_call)
}

pub(super) fn child_start_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![child_requested(ids), child_started(ids)]
}

fn child_requested(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.child_tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallRequested {
            tool_name: text("tree_sitter:query"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"fixture-child-input"),
            safe_option_names: vec![text("query")],
        },
    )
    .with_task(ids.task)
    .with_call(ids.child_tool_call)
    .with_parent(ids.tool_item)
}

fn child_started(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.child_tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallStarted {
            tool_name: text("tree_sitter:query"),
            runtime: Some(text("native")),
            model: None,
        },
    )
    .with_task(ids.task)
    .with_call(ids.child_tool_call)
    .with_parent(ids.tool_item)
}

pub(super) fn unavailable_model_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![
        unavailable_model_started(ids),
        unavailable_model_finished(ids),
    ]
}

fn unavailable_model_started(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.unavailable_model_item,
        RunItemSource::Runtime,
        RunItemV1::ModelCallStarted {
            provider: text("anthropic"),
            model: text("claude-usage-unavailable"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"fixture-unavailable-usage"),
        },
    )
    .with_task(ids.task)
    .with_call(ids.unavailable_model_call)
    .with_parent(ids.child_tool_item)
}

fn unavailable_model_finished(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.unavailable_model_item,
        RunItemSource::Runtime,
        RunItemV1::ModelCallFinished {
            provider: text("anthropic"),
            model: text("claude-usage-unavailable"),
            status: RunItemStatus::Completed,
            latency_ms: 40,
            usage: ModelUsage {
                input_tokens: None,
                output_tokens: None,
            },
            cost: RuntimeCostReport::UNAVAILABLE,
            error_class: None,
        },
    )
    .with_task(ids.task)
    .with_call(ids.unavailable_model_call)
    .with_parent(ids.child_tool_item)
}

pub(super) fn child_finish_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![safe_reasoning(ids), child_finished(ids)]
}

fn safe_reasoning(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.reasoning_item,
        RunItemSource::Runtime,
        RunItemV1::SafeReasoningSummary {
            text: text("AST evidence confirms the candidate source and sink"),
            redaction_policy_version: RUN_ITEM_REDACTION_POLICY_VERSION,
        },
    )
    .with_parent(ids.child_tool_item)
}

fn child_finished(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.child_tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: RuntimeCostReport::known(RuntimeCost::ZERO),
            result_artifact: None,
            preview: vec![text("query matched source"), text("query matched sink")],
            warning_count: 0,
            error_count: 0,
        },
    )
    .with_task(ids.task)
    .with_call(ids.child_tool_call)
    .with_parent(ids.tool_item)
}

pub(super) fn outer_execution_records(
    ids: FixtureIds,
    exact: RuntimeCostReport,
) -> Vec<RunItemRecord> {
    vec![
        outer_progress(ids),
        exact_model_started(ids),
        exact_model_finished(ids, exact),
        progress_loss(ids),
    ]
}

fn outer_progress(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.tool_item,
        RunItemSource::Runtime,
        RunItemV1::ToolCallProgress {
            message: text("checking source-backed proof"),
            completed: Some(1),
            total: Some(2),
        },
    )
    .with_task(ids.task)
    .with_call(ids.tool_call)
}

fn exact_model_started(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.model_item,
        RunItemSource::Runtime,
        RunItemV1::ModelCallStarted {
            provider: text("anthropic"),
            model: text("claude-fixture"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"fixture-model-input"),
        },
    )
    .with_task(ids.task)
    .with_call(ids.model_call)
    .with_parent(ids.tool_item)
}

fn exact_model_finished(ids: FixtureIds, exact: RuntimeCostReport) -> RunItemRecord {
    record(
        ids.model_item,
        RunItemSource::Runtime,
        RunItemV1::ModelCallFinished {
            provider: text("anthropic"),
            model: text("claude-fixture"),
            status: RunItemStatus::Completed,
            latency_ms: 125,
            usage: ModelUsage {
                input_tokens: Some(1_234),
                output_tokens: Some(321),
            },
            cost: exact,
            error_class: None,
        },
    )
    .with_task(ids.task)
    .with_call(ids.model_call)
    .with_parent(ids.tool_item)
}

fn progress_loss(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.progress_loss_item,
        RunItemSource::Persistence,
        RunItemV1::ProgressTruncated {
            progress_item_id: ids.tool_item,
            omitted_count: 7,
        },
    )
}

pub(super) fn outer_finish(
    ids: FixtureIds,
    exact: RuntimeCostReport,
    result_reference: ArtifactReference,
) -> RunItemRecord {
    record(
        ids.tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Completed,
            cost: exact,
            result_artifact: Some(result_reference),
            preview: vec![text("proof reproduced"), text("result persisted")],
            warning_count: 10,
            error_count: 10,
        },
    )
    .with_task(ids.task)
    .with_call(ids.tool_call)
}
