use super::super::super::{
    PhaseReceiptProjection, QuestionDecisionProjection, QuestionProjection, RunProjection,
};
use crate::run_lifecycle::{OperatorDecisionValue, RunItemEnvelopeV1, RunItemV1, RunQuestionId};
use anyhow::Result;

pub(super) fn apply_domain_item(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    match &envelope.item {
        RunItemV1::ArtifactProduced { artifact } => apply_artifact(projection, envelope, artifact),
        RunItemV1::FindingDelta { delta } => {
            projection.finding_deltas.push(delta.clone());
            Ok(())
        }
        RunItemV1::OperatorQuestion { .. } => apply_question(projection, envelope),
        RunItemV1::OperatorDecision { .. } => apply_decision_item(projection, envelope),
        RunItemV1::TerminalOutcome { .. } => {
            super::reducer_terminal::apply_terminal_item(projection, envelope)
        }
        RunItemV1::PhaseReceipt { .. } => apply_phase_receipt(projection, envelope),
        RunItemV1::ProgressTruncated { omitted_count, .. } => {
            add_omitted_progress(projection, *omitted_count)
        }
        RunItemV1::DiagnosticNotice { message, .. }
            if message.as_str() == crate::run_lifecycle::RUN_PROGRESS_SATURATION_MARKER =>
        {
            projection.progress_saturated = true;
            Ok(())
        }
        RunItemV1::SafeReasoningSummary { .. } | RunItemV1::DiagnosticNotice { .. } => Ok(()),
        _ => unreachable!("call and work items are handled before domain items"),
    }
}

fn apply_artifact(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    artifact: &crate::run_lifecycle::ArtifactReference,
) -> Result<()> {
    let producer = projection
        .calls
        .iter_mut()
        .find(|(_, call)| call.item_id == artifact.producing_item_id);
    let (call_id, call) =
        producer.ok_or_else(|| anyhow::anyhow!("artifact references an unknown producing call"))?;
    validate_artifact_call_scope(envelope, *call_id)?;
    validate_producing_call(call, artifact)?;
    call.related_artifact_ids.push(envelope.item_id);
    anyhow::ensure!(
        !projection.artifacts.contains_key(&envelope.item_id),
        "artifact item ID was produced twice"
    );
    projection
        .artifacts
        .insert(envelope.item_id, artifact.clone());
    Ok(())
}

fn validate_artifact_call_scope(
    envelope: &RunItemEnvelopeV1,
    producing_call_id: crate::run_lifecycle::RunCallId,
) -> Result<()> {
    let call_id = envelope
        .call_id
        .ok_or_else(|| anyhow::anyhow!("artifact lacks call scope"))?;
    anyhow::ensure!(
        call_id == producing_call_id,
        "artifact call scope does not match its producing call"
    );
    Ok(())
}

fn validate_producing_call(
    call: &crate::run_lifecycle::CallProjection,
    artifact: &crate::run_lifecycle::ArtifactReference,
) -> Result<()> {
    if is_scan_start_source(call, artifact) {
        return Ok(());
    }
    anyhow::ensure!(
        call.status.is_terminal(),
        "artifact producer call is not terminal"
    );
    if artifact.path.as_str() == "result.json" {
        let result_artifact = call
            .result_artifact
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("result artifact was not linked by call settlement"))?;
        anyhow::ensure!(
            result_artifact == artifact,
            "artifact conflicts with canonical result"
        );
    }
    Ok(())
}

fn is_scan_start_source(
    call: &crate::run_lifecycle::CallProjection,
    artifact: &crate::run_lifecycle::ArtifactReference,
) -> bool {
    use crate::run_lifecycle::{CallKind, RunItemStatus};
    matches!(
        (call.kind, call.status, call.label.as_str()),
        (CallKind::Tool, RunItemStatus::Running, "sast:scan")
    ) && artifact.path.as_str()
        == crate::artifact_contract::scan_start_source_artifact_leaf(call.item_id)
}

fn apply_question(projection: &mut RunProjection, envelope: &RunItemEnvelopeV1) -> Result<()> {
    let RunItemV1::OperatorQuestion {
        question_id,
        prompt,
        choices,
        authorization_scope,
    } = &envelope.item
    else {
        unreachable!("caller classified an operator question")
    };
    anyhow::ensure!(
        !projection.questions.contains_key(question_id),
        "question was emitted twice"
    );
    projection.questions.insert(
        *question_id,
        QuestionProjection {
            question_id: *question_id,
            item_id: envelope.item_id,
            prompt: prompt.clone(),
            choices: choices.clone(),
            authorization_scope: authorization_scope.clone(),
            source: envelope.source,
            occurred_at_ms: envelope.occurred_at_ms,
            decision: None,
        },
    );
    Ok(())
}

fn apply_decision_item(projection: &mut RunProjection, envelope: &RunItemEnvelopeV1) -> Result<()> {
    let RunItemV1::OperatorDecision {
        question_id,
        decision,
        authorization_scope,
    } = &envelope.item
    else {
        unreachable!("caller classified an operator decision")
    };
    apply_decision(
        projection,
        envelope,
        *question_id,
        decision.clone(),
        authorization_scope,
    )
}

fn apply_decision(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    question_id: RunQuestionId,
    decision: OperatorDecisionValue,
    authorization_scope: &crate::run_lifecycle::SafeText,
) -> Result<()> {
    if !projection.questions.contains_key(&question_id) {
        anyhow::bail!("decision has no question");
    }
    let question = projection
        .questions
        .get_mut(&question_id)
        .expect("question existence checked above");
    validate_decision_identity(question, envelope, authorization_scope)?;
    validate_selected_choice(question, &decision)?;
    question.decision = Some(QuestionDecisionProjection {
        item_id: envelope.item_id,
        occurred_at_ms: envelope.occurred_at_ms,
        source: envelope.source,
        authorization_scope: authorization_scope.clone(),
        value: decision,
    });
    Ok(())
}

fn validate_decision_identity(
    question: &QuestionProjection,
    envelope: &RunItemEnvelopeV1,
    authorization_scope: &crate::run_lifecycle::SafeText,
) -> Result<()> {
    anyhow::ensure!(
        question.item_id == envelope.item_id,
        "question item ID changed at decision"
    );
    anyhow::ensure!(question.decision.is_none(), "question decided twice");
    anyhow::ensure!(
        question.authorization_scope == *authorization_scope,
        "question decision authorization scope changed"
    );
    Ok(())
}

fn validate_selected_choice(
    question: &QuestionProjection,
    decision: &OperatorDecisionValue,
) -> Result<()> {
    let OperatorDecisionValue::Selected { choice_id } = decision else {
        return Ok(());
    };
    anyhow::ensure!(
        question
            .choices
            .iter()
            .any(|choice| choice.id == *choice_id),
        "question decision references an unknown choice identity"
    );
    Ok(())
}

fn apply_phase_receipt(projection: &mut RunProjection, envelope: &RunItemEnvelopeV1) -> Result<()> {
    let receipt = receipt_projection(projection, envelope)?;
    anyhow::ensure!(
        projection.phase_receipt.is_none(),
        "phase receipt already exists"
    );
    validate_interaction_count(projection, &receipt)?;
    projection.continuation = Some(receipt.continuation.clone());
    projection.phase_receipt = Some(receipt);
    Ok(())
}

fn receipt_projection(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Result<PhaseReceiptProjection> {
    let RunItemV1::PhaseReceipt {
        run_ids,
        status,
        cost,
        finding_delta,
        artifact_ids,
        interaction_count,
        offered_actions,
        continuation,
    } = &envelope.item
    else {
        unreachable!("caller classified a phase receipt")
    };
    let _ = projection;
    Ok(PhaseReceiptProjection {
        item_id: envelope.item_id,
        run_ids: run_ids.clone(),
        status: *status,
        cost: *cost,
        finding_delta: finding_delta.clone(),
        artifact_ids: artifact_ids.clone(),
        interaction_count: *interaction_count,
        offered_actions: offered_actions.clone(),
        continuation: continuation.clone(),
        occurred_at_ms: envelope.occurred_at_ms,
    })
}

fn validate_interaction_count(
    projection: &RunProjection,
    receipt: &PhaseReceiptProjection,
) -> Result<()> {
    let decisions = projection
        .questions
        .values()
        .filter(|question| question.decision.is_some())
        .count() as u64;
    let valid = if receipt.run_ids.len() == 1 {
        receipt.interaction_count == decisions
    } else {
        receipt.interaction_count >= decisions
    };
    anyhow::ensure!(
        valid,
        "phase receipt interaction count contradicts typed decisions"
    );
    Ok(())
}

fn add_omitted_progress(projection: &mut RunProjection, omitted_count: u64) -> Result<()> {
    projection.omitted_progress_count = projection
        .omitted_progress_count
        .checked_add(omitted_count)
        .ok_or_else(|| anyhow::anyhow!("progress truncation count overflow"))?;
    Ok(())
}
