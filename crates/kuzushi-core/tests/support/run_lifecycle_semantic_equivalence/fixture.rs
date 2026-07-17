//! Shared deterministic lifecycle records for cross-crate presentation tests.

use kuzushi_core::run_lifecycle::{
    ArtifactReference, FindingDeltaSummary, OperatorChoice, RunCallId, RunItemId, RunItemRecord,
    RunItemSource, RunItemStatus, RunItemV1, RunQuestionId, RunTaskId, SafeText,
    WorkflowContinuation,
};
use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
use std::path::Path;

#[path = "fixture/complete.rs"]
mod complete;
#[path = "fixture/partial.rs"]
mod partial;

pub(super) const COMPLETE_RUN_ID: &str = "semantic-equivalence-complete";
pub(super) const PARTIAL_RUN_ID: &str = "semantic-equivalence-partial";
pub(super) const DEGRADED_RUN_ID: &str = "semantic-equivalence-degraded";
pub(super) const LEGACY_RUN_ID: &str = "semantic-equivalence-legacy";

#[derive(Debug, Clone, Copy)]
pub(super) struct FixtureIds {
    pub(super) plan_item: RunItemId,
    pub(super) task_item: RunItemId,
    pub(super) tool_item: RunItemId,
    pub(super) child_tool_item: RunItemId,
    pub(super) model_item: RunItemId,
    pub(super) unavailable_model_item: RunItemId,
    pub(super) reasoning_item: RunItemId,
    pub(super) progress_loss_item: RunItemId,
    pub(super) artifact_item: RunItemId,
    pub(super) finding_item: RunItemId,
    pub(super) question_item: RunItemId,
    pub(super) diagnostic_item: RunItemId,
    pub(super) terminal_item: RunItemId,
    pub(super) receipt_item: RunItemId,
    pub(super) task: RunTaskId,
    pub(super) tool_call: RunCallId,
    pub(super) child_tool_call: RunCallId,
    pub(super) model_call: RunCallId,
    pub(super) unavailable_model_call: RunCallId,
    pub(super) question: RunQuestionId,
}

impl FixtureIds {
    pub(super) fn fixed() -> Self {
        Self {
            plan_item: item_id(1),
            task_item: item_id(2),
            tool_item: item_id(3),
            child_tool_item: item_id(12),
            model_item: item_id(4),
            unavailable_model_item: item_id(13),
            reasoning_item: item_id(14),
            progress_loss_item: item_id(5),
            artifact_item: item_id(6),
            finding_item: item_id(7),
            question_item: item_id(8),
            diagnostic_item: item_id(9),
            terminal_item: item_id(10),
            receipt_item: item_id(11),
            task: task_id(1),
            tool_call: call_id(1),
            child_tool_call: call_id(3),
            model_call: call_id(2),
            unavailable_model_call: call_id(4),
            question: question_id(1),
        }
    }
}

pub(super) fn complete_records(
    run_id: &str,
    ids: FixtureIds,
    result_reference: ArtifactReference,
) -> Vec<RunItemRecord> {
    complete::records(run_id, ids, result_reference)
}

pub(super) fn partial_records(run_id: &str, ids: FixtureIds) -> Vec<RunItemRecord> {
    partial::records(run_id, ids)
}

pub(super) fn terminal_status_records(run_id: &str, status: RunItemStatus) -> Vec<RunItemRecord> {
    vec![terminal_status_record(run_id, status)]
}

pub(super) fn outstanding_decision_records(run_id: &str, ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![
        outstanding_question(ids),
        awaiting_decision_terminal(run_id, ids),
    ]
}

fn terminal_status_record(run_id: &str, status: RunItemStatus) -> RunItemRecord {
    record(
        item_id(0x500 + status_ordinal(status)),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status,
            summary: text(format!("{} status fixture", status.label())),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: text(format!("{run_id} settled")),
            },
        },
    )
}

fn outstanding_question(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.question_item,
        RunItemSource::Operator,
        RunItemV1::OperatorQuestion {
            question_id: ids.question,
            prompt: text("Choose how to continue"),
            choices: vec![OperatorChoice {
                id: text("inspect"),
                label: text("Inspect"),
            }],
            authorization_scope: text("run:outstanding-decision"),
        },
    )
}

fn awaiting_decision_terminal(run_id: &str, ids: FixtureIds) -> RunItemRecord {
    record(
        ids.terminal_item,
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Partial,
            summary: text(format!("{run_id}: operator decision required")),
            cost: RuntimeCostReport::UNAVAILABLE,
            continuation: WorkflowContinuation::AwaitDecision {
                question_id: ids.question,
            },
        },
    )
}

fn status_ordinal(status: RunItemStatus) -> u128 {
    match status {
        RunItemStatus::Completed => 1,
        RunItemStatus::Partial => 2,
        RunItemStatus::Skipped => 3,
        RunItemStatus::Failed => 4,
        RunItemStatus::Canceled => 5,
        RunItemStatus::Interrupted => 6,
        RunItemStatus::Pending | RunItemStatus::Running => 0,
    }
}

pub(super) fn write_bounded_result(
    target: &Path,
    run_id: &str,
    producer: RunItemId,
) -> ArtifactReference {
    let output = (1..=14)
        .map(|line| format!("Result line {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    let warnings = numbered_messages("bounded warning", 10);
    let errors = numbered_messages("bounded error", 10);
    let result = bounded_result_json(output, warnings, errors);
    kuzushi_core::run_artifacts::write_run_artifact_json(
        target,
        run_id,
        "result.json",
        "tool result",
        &result,
    )
    .unwrap();
    kuzushi_core::run_lifecycle::verified_result_artifact_reference(target, run_id, producer)
        .unwrap()
}

fn numbered_messages(label: &str, count: usize) -> Vec<String> {
    (1..=count)
        .map(|index| format!("{label} {index}"))
        .collect()
}

fn bounded_result_json(
    output: String,
    warnings: Vec<String>,
    errors: Vec<String>,
) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "status": "completed",
        "summary": "verified bounded fixture result",
        "output": output,
        "warnings": warnings,
        "errors": errors,
        "artifacts": [{
            "label": "reproduced proof",
            "path": "proof.json",
            "kind": "json"
        }],
        "data": { "tool": "verification:verify" }
    })
}

pub(super) fn record(item_id: RunItemId, source: RunItemSource, item: RunItemV1) -> RunItemRecord {
    RunItemRecord::new(item_id, source, item)
}

pub(super) fn task_record(
    ids: FixtureIds,
    status: RunItemStatus,
    detail: Option<&str>,
) -> RunItemRecord {
    record(
        ids.task_item,
        RunItemSource::Workflow,
        RunItemV1::TaskUpdated {
            title: text("verification:verify"),
            status,
            detail: detail.map(text),
        },
    )
    .with_task(ids.task)
}

pub(super) fn proof_reference(ids: FixtureIds) -> ArtifactReference {
    ArtifactReference {
        path: text("proof.json"),
        kind: text("proof"),
        label: text("reproduced proof"),
        digest: text("sha256:fixture-proof-digest"),
        byte_count: 256,
        line_count: Some(8),
        producing_item_id: ids.tool_item,
    }
}

pub(super) fn finding_delta() -> FindingDeltaSummary {
    FindingDeltaSummary {
        added: 0,
        updated: 1,
        removed: 0,
        store_watermark: text("fixture-watermark-1"),
        finding_id_samples: vec![text("fixture-001")],
    }
}

pub(super) fn empty_finding_delta() -> FindingDeltaSummary {
    FindingDeltaSummary {
        added: 0,
        updated: 0,
        removed: 0,
        store_watermark: text("fixture-watermark-0"),
        finding_id_samples: Vec::new(),
    }
}

pub(super) fn exact_cost(value: f64) -> RuntimeCostReport {
    RuntimeCostReport::known(RuntimeCost::from_usd(value, "fixture exact cost").unwrap())
}

pub(super) fn incomplete_cost(value: f64) -> RuntimeCostReport {
    RuntimeCostReport::incomplete(RuntimeCost::from_usd(value, "fixture incomplete cost").unwrap())
}

pub(super) fn text(value: impl AsRef<str>) -> SafeText {
    SafeText::operator_visible(value)
}

fn item_id(value: u128) -> RunItemId {
    RunItemId::parse(&uuid::Uuid::from_u128(value).to_string()).unwrap()
}

fn task_id(value: u128) -> RunTaskId {
    RunTaskId::parse(&uuid::Uuid::from_u128(0x100 + value).to_string()).unwrap()
}

fn call_id(value: u128) -> RunCallId {
    RunCallId::parse(&uuid::Uuid::from_u128(0x200 + value).to_string()).unwrap()
}

fn question_id(value: u128) -> RunQuestionId {
    RunQuestionId::parse(&uuid::Uuid::from_u128(0x300 + value).to_string()).unwrap()
}
