use super::*;

pub(super) fn attention_cells(projection: &RunProjection) -> Vec<RunPresentationCellV1> {
    projection
        .timeline
        .iter()
        .filter_map(|envelope| attention_cell(projection, envelope))
        .collect()
}

fn attention_cell(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Option<RunPresentationCellV1> {
    match &envelope.item {
        RunItemV1::OperatorQuestion {
            question_id,
            prompt,
            choices,
            authorization_scope,
        } => Some(question_cell(
            envelope.item_id,
            *question_id,
            prompt,
            choices,
            authorization_scope,
            question_is_resolved(projection, *question_id),
        )),
        RunItemV1::OperatorDecision {
            question_id,
            decision,
            authorization_scope,
        } => Some(decision_cell(
            envelope.item_id,
            *question_id,
            decision,
            authorization_scope,
        )),
        _ => None,
    }
}

fn question_is_resolved(projection: &RunProjection, question_id: RunQuestionId) -> bool {
    projection
        .questions
        .get(&question_id)
        .is_some_and(|question| question.decision.is_some())
}

fn question_cell(
    item_id: RunItemId,
    question_id: RunQuestionId,
    prompt: &SafeText,
    choices: &[OperatorChoice],
    authorization_scope: &SafeText,
    resolved: bool,
) -> RunPresentationCellV1 {
    let (state, prompt, choices) = if resolved {
        (QuestionPresentationStateV1::Resolved, None, Vec::new())
    } else {
        (
            QuestionPresentationStateV1::AwaitingDecision,
            Some(prompt.clone()),
            choices.to_vec(),
        )
    };
    cell(
        RunCellKey::item(item_id, RunCellRoleV1::Question, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::Question(QuestionPresentationV1 {
            question_id,
            state,
            prompt,
            choices,
            authorization_scope: authorization_scope.clone(),
        }),
    )
}

fn decision_cell(
    item_id: RunItemId,
    question_id: RunQuestionId,
    decision: &OperatorDecisionValue,
    authorization_scope: &SafeText,
) -> RunPresentationCellV1 {
    cell(
        RunCellKey::item(item_id, RunCellRoleV1::Decision, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::Decision(DecisionPresentationV1 {
            question_id,
            decision: decision.clone(),
            authorization_scope: authorization_scope.clone(),
        }),
    )
}

pub(super) fn outcome_cells(
    projection: &RunProjection,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> Vec<RunPresentationCellV1> {
    projection
        .timeline
        .iter()
        .filter_map(|envelope| outcome_cell(envelope, quarantine))
        .collect()
}

fn outcome_cell(
    envelope: &RunItemEnvelopeV1,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> Option<RunPresentationCellV1> {
    match &envelope.item {
        RunItemV1::TerminalOutcome {
            status,
            summary,
            cost,
            continuation,
        } => Some(terminal_cell(
            envelope.item_id,
            *status,
            summary,
            *cost,
            continuation,
            quarantine,
        )),
        RunItemV1::PhaseReceipt { .. } => phase_receipt_payload(&envelope.item)
            .map(|receipt| phase_receipt_cell(envelope.item_id, receipt, quarantine)),
        _ => None,
    }
}

fn phase_receipt_payload(item: &RunItemV1) -> Option<PhaseReceiptPresentationV1> {
    let RunItemV1::PhaseReceipt {
        run_ids,
        status,
        cost,
        finding_delta,
        artifact_ids,
        interaction_count,
        offered_actions,
        continuation,
    } = item
    else {
        return None;
    };
    Some(PhaseReceiptPresentationV1 {
        run_ids: run_ids.clone(),
        status: *status,
        cost: *cost,
        finding_delta: finding_delta.clone(),
        artifact_ids: artifact_ids.clone(),
        interaction_count: *interaction_count,
        offered_actions: offered_actions.clone(),
        continuation: continuation.clone(),
    })
}

fn terminal_cell(
    item_id: RunItemId,
    status: RunItemStatus,
    summary: &SafeText,
    cost: RuntimeCostReport,
    continuation: &WorkflowContinuation,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> RunPresentationCellV1 {
    let presented_status = quarantine.map_or(status, |quarantine| quarantine.status(status));
    let presented_continuation = quarantine.map_or_else(
        || continuation.clone(),
        |quarantine| quarantine.continuation(),
    );
    let terminal = cell(
        RunCellKey::item(item_id, RunCellRoleV1::TerminalOutcome, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::Terminal(TerminalPresentationV1 {
            status: presented_status,
            summary: summary.clone(),
            cost,
            continuation: presented_continuation,
        }),
    );
    match quarantine {
        Some(quarantine) => quarantine.qualify(terminal, status),
        None => terminal,
    }
}

fn phase_receipt_cell(
    item_id: RunItemId,
    mut receipt: PhaseReceiptPresentationV1,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> RunPresentationCellV1 {
    let recorded_status = receipt.status;
    if let Some(quarantine) = quarantine {
        receipt.status = quarantine.status(recorded_status);
        receipt.continuation = quarantine.continuation();
        receipt.offered_actions = quarantine.offered_actions();
    }
    let receipt_cell = cell(
        RunCellKey::item(item_id, RunCellRoleV1::PhaseReceipt, 0),
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::PhaseReceipt(receipt),
    );
    match quarantine {
        Some(quarantine) => quarantine.qualify(receipt_cell, recorded_status),
        None => receipt_cell,
    }
}
