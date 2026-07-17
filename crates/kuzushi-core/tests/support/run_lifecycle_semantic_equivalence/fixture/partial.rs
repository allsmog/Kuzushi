//! Partial typed-run fixture assembly.

use super::*;
use kuzushi_core::run_lifecycle::{ModelUsage, OperationFingerprint, RunId, WorkflowContinuation};

pub(super) fn records(run_id: &str, ids: FixtureIds) -> Vec<RunItemRecord> {
    let incomplete = incomplete_cost(0.004);
    let inspect = WorkflowContinuation::InspectRun {
        run_id: RunId::parse(run_id).unwrap(),
        reason: text("inspect incomplete evidence"),
    };
    let mut records = starting_work(ids);
    records.extend(tool_start(ids));
    records.extend(model_records(ids, incomplete));
    records.push(tool_finish(ids, incomplete));
    records.extend(closing_work(ids));
    records.extend(terminal_records(
        RunId::parse(run_id).unwrap(),
        ids,
        incomplete,
        inspect,
    ));
    records
}

fn starting_work(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![
        record(
            ids.plan_item,
            RunItemSource::Workflow,
            RunItemV1::PlanUpdated {
                revision: 1,
                title: text("verify one finding"),
                status: RunItemStatus::Pending,
                task_ids: vec![ids.task],
            },
        ),
        task_record(ids, RunItemStatus::Pending, None),
        task_record(ids, RunItemStatus::Running, Some("dispatching verifier")),
    ]
}

fn tool_start(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![tool_requested(ids), tool_started(ids)]
}

fn tool_requested(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallRequested {
            tool_name: text("verification:verify"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"partial-tool-input"),
            safe_option_names: vec![text("findingId")],
        },
    )
    .with_task(ids.task)
    .with_call(ids.tool_call)
}

fn tool_started(ids: FixtureIds) -> RunItemRecord {
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

fn model_records(ids: FixtureIds, incomplete: RuntimeCostReport) -> Vec<RunItemRecord> {
    vec![model_started(ids), model_finished(ids, incomplete)]
}

fn model_started(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.model_item,
        RunItemSource::Runtime,
        RunItemV1::ModelCallStarted {
            provider: text("anthropic"),
            model: text("claude-fixture"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"partial-model-input"),
        },
    )
    .with_task(ids.task)
    .with_call(ids.model_call)
    .with_parent(ids.tool_item)
}

fn model_finished(ids: FixtureIds, incomplete: RuntimeCostReport) -> RunItemRecord {
    record(
        ids.model_item,
        RunItemSource::Runtime,
        RunItemV1::ModelCallFinished {
            provider: text("anthropic"),
            model: text("claude-fixture"),
            status: RunItemStatus::Partial,
            latency_ms: 80,
            usage: ModelUsage {
                input_tokens: Some(210),
                output_tokens: None,
            },
            cost: incomplete,
            error_class: Some(text("usage_incomplete")),
        },
    )
    .with_task(ids.task)
    .with_call(ids.model_call)
    .with_parent(ids.tool_item)
}

fn tool_finish(ids: FixtureIds, incomplete: RuntimeCostReport) -> RunItemRecord {
    record(
        ids.tool_item,
        RunItemSource::Dispatch,
        RunItemV1::ToolCallFinished {
            status: RunItemStatus::Partial,
            cost: incomplete,
            result_artifact: None,
            preview: vec![
                text("evidence collection stopped early"),
                text("inspect the retained prefix"),
            ],
            warning_count: 1,
            error_count: 0,
        },
    )
    .with_task(ids.task)
    .with_call(ids.tool_call)
}

fn closing_work(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![
        task_record(
            ids,
            RunItemStatus::Partial,
            Some("evidence remains incomplete"),
        ),
        record(
            ids.plan_item,
            RunItemSource::Workflow,
            RunItemV1::PlanUpdated {
                revision: 2,
                title: text("verify one finding"),
                status: RunItemStatus::Partial,
                task_ids: vec![ids.task],
            },
        ),
    ]
}

fn terminal_records(
    run_id: RunId,
    ids: FixtureIds,
    incomplete: RuntimeCostReport,
    inspect: WorkflowContinuation,
) -> Vec<RunItemRecord> {
    vec![
        partial_terminal(ids, incomplete, inspect.clone()),
        partial_receipt(run_id, ids, incomplete, inspect),
    ]
}

fn partial_terminal(
    ids: FixtureIds,
    incomplete: RuntimeCostReport,
    inspect: WorkflowContinuation,
) -> RunItemRecord {
    record(
        ids.terminal_item,
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Partial,
            summary: text("verification partial"),
            cost: incomplete,
            continuation: inspect,
        },
    )
}

fn partial_receipt(
    run_id: RunId,
    ids: FixtureIds,
    incomplete: RuntimeCostReport,
    inspect: WorkflowContinuation,
) -> RunItemRecord {
    record(
        ids.receipt_item,
        RunItemSource::Workflow,
        RunItemV1::PhaseReceipt {
            run_ids: vec![run_id],
            status: RunItemStatus::Partial,
            cost: incomplete,
            finding_delta: empty_finding_delta(),
            artifact_ids: Vec::new(),
            interaction_count: 0,
            offered_actions: vec![inspect.clone()],
            continuation: inspect,
        },
    )
}
