use super::*;
use crate::run_lifecycle::{
    OperatorDecisionValue, QuestionDecisionProjection, QuestionProjection, RunItemSource,
    RunQuestionId, TerminalProjection,
};

fn projection(run_id: RunId, status: RunItemStatus) -> RunProjection {
    let mut projection = RunProjection {
        run_id: Some(run_id),
        ..RunProjection::default()
    };
    projection.terminal = Some(TerminalProjection {
        item_id: RunItemId::new(),
        status,
        summary: SafeText::operator_visible("settled"),
        cost: RuntimeCostReport::UNAVAILABLE,
        continuation: WorkflowContinuation::NoFurtherAction {
            reason: SafeText::operator_visible("await phase receipt"),
        },
    });
    projection
}

fn run_id() -> RunId {
    RunId::parse(&crate::run_artifacts::new_run_id("receipt-test")).unwrap()
}

fn question(question_id: RunQuestionId, decided: bool) -> QuestionProjection {
    QuestionProjection {
        question_id,
        item_id: RunItemId::new(),
        prompt: SafeText::operator_visible("Scope?"),
        choices: Vec::new(),
        authorization_scope: SafeText::operator_visible("run"),
        source: RunItemSource::Runtime,
        occurred_at_ms: 1,
        decision: decided.then(decision),
    }
}

fn decision() -> QuestionDecisionProjection {
    QuestionDecisionProjection {
        item_id: RunItemId::new(),
        occurred_at_ms: 2,
        source: RunItemSource::Operator,
        authorization_scope: SafeText::operator_visible("run"),
        value: OperatorDecisionValue::ProvidedFreeform,
    }
}

fn build(run_id: &RunId, projection: &RunProjection) -> Result<RunItemV1> {
    PhaseReceiptBuilder::new(
        WorkflowPhase::Scan,
        RunItemStatus::Completed,
        std::slice::from_ref(run_id),
        std::slice::from_ref(projection),
    )
    .build()
}

#[test]
fn derives_interactions_and_clean_scan_destination_from_typed_projection() {
    let run_id = run_id();
    let question_id = RunQuestionId::new();
    let mut projection = projection(run_id.clone(), RunItemStatus::Completed);
    projection.finding_deltas.push(FindingDeltaSummary {
        added: 0,
        updated: 0,
        removed: 0,
        store_watermark: SafeText::operator_visible("ledger:7"),
        finding_id_samples: Vec::new(),
    });
    projection
        .questions
        .insert(question_id, question(question_id, true));

    let item = build(&run_id, &projection).unwrap();

    assert!(matches!(
        item,
        RunItemV1::PhaseReceipt {
            interaction_count: 1,
            continuation: WorkflowContinuation::OpenReport { .. },
            ..
        }
    ));
}

#[test]
fn completed_receipt_rejects_non_complete_referenced_run() {
    let run_id = run_id();
    let projection = projection(run_id.clone(), RunItemStatus::Partial);

    let error = build(&run_id, &projection).unwrap_err();

    assert!(error.to_string().contains("non-complete run"));
}

#[test]
fn outstanding_question_is_the_primary_continuation() {
    let run_id = run_id();
    let question_id = RunQuestionId::new();
    let mut projection = projection(run_id.clone(), RunItemStatus::Completed);
    projection
        .questions
        .insert(question_id, question(question_id, false));

    let item = build(&run_id, &projection).unwrap();

    assert!(matches!(
        item,
        RunItemV1::PhaseReceipt {
            continuation: WorkflowContinuation::AwaitDecision { question_id: actual },
            ..
        } if actual == question_id
    ));

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    assert!(!offered_actions
        .iter()
        .any(|action| matches!(action, WorkflowContinuation::NoFurtherAction { .. })));
}

#[test]
fn completed_receipt_preserves_select_without_navigation() {
    let run_id = run_id();
    let projection = projection(run_id.clone(), RunItemStatus::Completed);

    let item = build(&run_id, &projection).unwrap();

    let RunItemV1::PhaseReceipt {
        offered_actions, ..
    } = item
    else {
        unreachable!();
    };
    assert!(offered_actions
        .iter()
        .any(|action| matches!(action, WorkflowContinuation::NoFurtherAction { .. })));
}
