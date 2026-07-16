//! Evidence, decision, and outcome records for the complete fixture.

use super::super::*;
use kuzushi_core::run_lifecycle::{
    FindingDeltaSummary, OperatorChoice, OperatorDecisionValue, RunId, WorkflowContinuation,
};

pub(super) fn evidence_records(ids: FixtureIds, delta: FindingDeltaSummary) -> Vec<RunItemRecord> {
    vec![
        record(
            ids.artifact_item,
            RunItemSource::Runtime,
            RunItemV1::ArtifactProduced {
                artifact: proof_reference(ids),
            },
        )
        .with_call(ids.tool_call)
        .with_parent(ids.tool_item),
        record(
            ids.finding_item,
            RunItemSource::Workflow,
            RunItemV1::FindingDelta { delta },
        ),
    ]
}

pub(super) fn decision_records(ids: FixtureIds) -> Vec<RunItemRecord> {
    vec![operator_question(ids), operator_decision(ids)]
}

fn operator_question(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.question_item,
        RunItemSource::Operator,
        RunItemV1::OperatorQuestion {
            question_id: ids.question,
            prompt: text("Accept reproduced proof?"),
            choices: vec![
                OperatorChoice {
                    id: text("accept"),
                    label: text("Accept"),
                },
                OperatorChoice {
                    id: text("defer"),
                    label: text("Defer"),
                },
            ],
            authorization_scope: text("finding:fixture-001"),
        },
    )
}

fn operator_decision(ids: FixtureIds) -> RunItemRecord {
    record(
        ids.question_item,
        RunItemSource::Operator,
        RunItemV1::OperatorDecision {
            question_id: ids.question,
            decision: OperatorDecisionValue::Selected {
                choice_id: text("accept"),
            },
            authorization_scope: text("finding:fixture-001"),
        },
    )
}

pub(super) fn terminal_records(
    run_id: RunId,
    ids: FixtureIds,
    exact: RuntimeCostReport,
    delta: FindingDeltaSummary,
    report: WorkflowContinuation,
) -> Vec<RunItemRecord> {
    vec![
        terminal_outcome(ids, exact, report.clone()),
        phase_receipt(run_id, ids, exact, delta, report),
    ]
}

fn terminal_outcome(
    ids: FixtureIds,
    exact: RuntimeCostReport,
    report: WorkflowContinuation,
) -> RunItemRecord {
    record(
        ids.terminal_item,
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Completed,
            summary: text("verification complete"),
            cost: exact,
            continuation: report,
        },
    )
}

fn phase_receipt(
    run_id: RunId,
    ids: FixtureIds,
    exact: RuntimeCostReport,
    delta: FindingDeltaSummary,
    report: WorkflowContinuation,
) -> RunItemRecord {
    record(
        ids.receipt_item,
        RunItemSource::Workflow,
        RunItemV1::PhaseReceipt {
            run_ids: vec![run_id],
            status: RunItemStatus::Completed,
            cost: exact,
            finding_delta: delta,
            artifact_ids: vec![ids.artifact_item],
            interaction_count: 1,
            offered_actions: vec![report.clone()],
            continuation: report,
        },
    )
}
