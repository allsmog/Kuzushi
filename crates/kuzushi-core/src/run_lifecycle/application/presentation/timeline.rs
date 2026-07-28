use super::*;

pub(super) fn timeline_cells(
    projection: &RunProjection,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> Vec<RunPresentationCellV1> {
    let mut ordinals = BTreeMap::<(RunItemId, RunCellRoleV1), u64>::new();
    projection
        .timeline
        .iter()
        .filter_map(|envelope| timeline_cell(projection, envelope, quarantine, &mut ordinals))
        .collect()
}

fn timeline_cell(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> Option<RunPresentationCellV1> {
    match &envelope.item {
        RunItemV1::ToolCallProgress {
            message,
            completed,
            total,
        } => Some(progress_cell(
            envelope, message, *completed, *total, ordinals,
        )),
        RunItemV1::SafeReasoningSummary {
            text,
            redaction_policy_version,
        } => Some(reasoning_cell(
            envelope,
            text,
            *redaction_policy_version,
            ordinals,
        )),
        RunItemV1::DiagnosticNotice { level, message } => {
            Some(diagnostic_cell(envelope, level, message, ordinals))
        }
        RunItemV1::ProgressTruncated {
            progress_item_id,
            omitted_count,
        } => Some(disclosure_cell(
            envelope,
            *progress_item_id,
            *omitted_count,
            ordinals,
        )),
        _ => lifecycle_event(projection, envelope)
            .map(|event| lifecycle_event_cell(envelope, event, quarantine, ordinals)),
    }
}

fn lifecycle_event(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Option<LifecycleEventPresentationV1> {
    match &envelope.item {
        RunItemV1::PlanUpdated { .. } | RunItemV1::TaskUpdated { .. } => work_event(envelope),
        RunItemV1::ToolCallRequested { .. }
        | RunItemV1::ToolCallRejected { .. }
        | RunItemV1::ToolCallStarted { .. }
        | RunItemV1::ToolCallFinished { .. } => tool_event(projection, envelope),
        RunItemV1::ModelCallStarted { .. } | RunItemV1::ModelCallFinished { .. } => {
            model_event(envelope)
        }
        RunItemV1::ArtifactProduced { .. } | RunItemV1::FindingDelta { .. } => {
            evidence_event(envelope)
        }
        RunItemV1::OperatorQuestion { .. } | RunItemV1::OperatorDecision { .. } => {
            interaction_event(projection, envelope)
        }
        RunItemV1::TerminalOutcome { .. } | RunItemV1::PhaseReceipt { .. } => {
            outcome_event(envelope)
        }
        _ => None,
    }
}

fn work_event(envelope: &RunItemEnvelopeV1) -> Option<LifecycleEventPresentationV1> {
    use LifecycleEventKindV1::{Plan, Task};
    match &envelope.item {
        RunItemV1::PlanUpdated {
            revision,
            title,
            status,
            ..
        } => Some(event(
            Plan,
            envelope,
            title,
            Some(*status),
            Some(format!("revision {revision}")),
        )),
        RunItemV1::TaskUpdated {
            title,
            status,
            detail,
        } => Some(event(Task, envelope, title, Some(*status), safe_detail(detail))),
        _ => None,
    }
}

fn tool_event(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Option<LifecycleEventPresentationV1> {
    use LifecycleEventKindV1::*;
    match &envelope.item {
        RunItemV1::ToolCallRequested { tool_name, .. } => Some(event(
            ToolRequested,
            envelope,
            tool_name,
            Some(RunItemStatus::Pending),
            None,
        )),
        RunItemV1::ToolCallRejected { reason_class, detail } => Some(event(
            ToolRejected,
            envelope,
            &call_label(projection, envelope),
            Some(RunItemStatus::Blocked),
            Some(format!("{reason_class} · {detail}")),
        )),
        RunItemV1::ToolCallStarted { tool_name, .. } => Some(event(
            ToolStarted,
            envelope,
            tool_name,
            Some(RunItemStatus::Running),
            None,
        )),
        RunItemV1::ToolCallFinished { .. } => Some(finished_tool_event(projection, envelope)),
        _ => None,
    }
}

fn finished_tool_event(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> LifecycleEventPresentationV1 {
    let RunItemV1::ToolCallFinished {
        status,
        cost,
        preview,
        warning_count,
        error_count,
        ..
    } = &envelope.item
    else {
        unreachable!("caller classified a finished tool call")
    };
    event(
        LifecycleEventKindV1::ToolFinished,
        envelope,
        &call_label(projection, envelope),
        Some(*status),
        finish_detail(preview, *warning_count, *error_count),
    )
    .with_cost(*cost)
}

fn model_event(envelope: &RunItemEnvelopeV1) -> Option<LifecycleEventPresentationV1> {
    use LifecycleEventKindV1::{ModelFinished, ModelStarted};
    match &envelope.item {
        RunItemV1::ModelCallStarted {
            provider, model, ..
        } => Some(event(
            ModelStarted,
            envelope,
            &SafeText::operator_visible(format!("{provider}/{model}")),
            Some(RunItemStatus::Running),
            None,
        )),
        RunItemV1::ModelCallFinished {
            provider,
            model,
            status,
            latency_ms,
            cost,
            error_class,
            failure,
            ..
        } => Some(
            event(
                ModelFinished,
                envelope,
                &SafeText::operator_visible(format!("{provider}/{model}")),
                Some(*status),
                model_failure_detail(error_class, failure.as_ref()),
            )
            .with_call_metrics(*latency_ms, *cost),
        ),
        _ => None,
    }
}

fn model_failure_detail(
    error_class: &Option<SafeText>,
    failure: Option<&crate::runtime::RuntimeFailureMetadata>,
) -> Option<String> {
    let Some(failure) = failure else {
        return safe_detail(error_class);
    };
    let mut parts = vec![format!("class={}", failure.error_class)];
    if let Some(stage) = failure.stage.as_deref() {
        parts.push(format!("stage={stage}"));
    }
    if let Some(status) = failure.http_status {
        parts.push(format!("http={status}"));
    }
    Some(parts.join(" · "))
}

fn evidence_event(envelope: &RunItemEnvelopeV1) -> Option<LifecycleEventPresentationV1> {
    use LifecycleEventKindV1::{ArtifactProduced, FindingsChanged};
    match &envelope.item {
        RunItemV1::ArtifactProduced { artifact } => Some(event(
            ArtifactProduced,
            envelope,
            &artifact.label,
            None,
            Some(artifact.path.to_string()),
        )),
        RunItemV1::FindingDelta { delta } => Some(event(
            FindingsChanged,
            envelope,
            &SafeText::operator_visible(format!(
                "+{} ~{} -{}",
                delta.added, delta.updated, delta.removed
            )),
            None,
            None,
        )),
        _ => None,
    }
}

fn interaction_event(
    projection: &RunProjection,
    envelope: &RunItemEnvelopeV1,
) -> Option<LifecycleEventPresentationV1> {
    use LifecycleEventKindV1::{OperatorDecision, OperatorQuestion};
    match &envelope.item {
        RunItemV1::OperatorQuestion {
            question_id, prompt, ..
        } => Some(event(
            OperatorQuestion,
            envelope,
            prompt,
            resolved_question_status(projection, *question_id),
            None,
        )),
        RunItemV1::OperatorDecision { decision, .. } => Some(event(
            OperatorDecision,
            envelope,
            &decision_label(decision),
            None,
            None,
        )),
        _ => None,
    }
}

fn decision_label(decision: &OperatorDecisionValue) -> SafeText {
    let label = match decision {
        OperatorDecisionValue::Selected { choice_id } => format!("selected {choice_id}"),
        OperatorDecisionValue::ProvidedFreeform => "response provided".to_string(),
        OperatorDecisionValue::Approved => "approved".to_string(),
        OperatorDecisionValue::Denied => "denied".to_string(),
        OperatorDecisionValue::Deferred => "deferred".to_string(),
    };
    SafeText::operator_visible(label)
}

fn resolved_question_status(
    projection: &RunProjection,
    question_id: RunQuestionId,
) -> Option<RunItemStatus> {
    projection
        .questions
        .get(&question_id)
        .and_then(|question| question.decision.as_ref())
        .map(|_| RunItemStatus::Completed)
}

fn outcome_event(envelope: &RunItemEnvelopeV1) -> Option<LifecycleEventPresentationV1> {
    use LifecycleEventKindV1::{PhaseReceipt, TerminalOutcome};
    match &envelope.item {
        RunItemV1::TerminalOutcome {
            status,
            summary,
            cost,
            ..
        } => Some(event(TerminalOutcome, envelope, summary, Some(*status), None).with_cost(*cost)),
        RunItemV1::PhaseReceipt { status, cost, .. } => Some(
            event(
                PhaseReceipt,
                envelope,
                &SafeText::operator_visible("phase receipt recorded"),
                Some(*status),
                None,
            )
            .with_cost(*cost),
        ),
        _ => None,
    }
}

fn event(
    kind: LifecycleEventKindV1,
    envelope: &RunItemEnvelopeV1,
    subject: &SafeText,
    status: Option<RunItemStatus>,
    detail: Option<String>,
) -> LifecycleEventPresentationV1 {
    LifecycleEventPresentationV1 {
        kind,
        occurred_at_ms: envelope.occurred_at_ms,
        subject: subject.clone(),
        status,
        detail: detail.map(SafeText::condensed_line),
        latency_ms: None,
        cost: None,
    }
}

trait LifecycleEventMetrics {
    fn with_cost(self, cost: crate::runtime::RuntimeCostReport) -> Self;
    fn with_call_metrics(self, latency_ms: u64, cost: crate::runtime::RuntimeCostReport) -> Self;
}

impl LifecycleEventMetrics for LifecycleEventPresentationV1 {
    fn with_cost(mut self, cost: crate::runtime::RuntimeCostReport) -> Self {
        self.cost = Some(cost);
        self
    }

    fn with_call_metrics(mut self, latency_ms: u64, cost: crate::runtime::RuntimeCostReport) -> Self {
        self.latency_ms = Some(latency_ms);
        self.cost = Some(cost);
        self
    }
}

fn safe_detail(value: &Option<SafeText>) -> Option<String> {
    value.as_ref().map(ToString::to_string)
}

fn call_label(projection: &RunProjection, envelope: &RunItemEnvelopeV1) -> SafeText {
    envelope
        .call_id
        .and_then(|call_id| projection.calls.get(&call_id))
        .map(|call| call.label.clone())
        .unwrap_or_else(|| SafeText::operator_visible("tool call"))
}

fn finish_detail(preview: &[SafeText], warnings: u64, errors: u64) -> Option<String> {
    preview.first().map(ToString::to_string).or_else(|| {
        (warnings > 0 || errors > 0).then(|| format!("{warnings} warning(s) · {errors} error(s)"))
    })
}

fn lifecycle_event_cell(
    envelope: &RunItemEnvelopeV1,
    mut event: LifecycleEventPresentationV1,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> RunPresentationCellV1 {
    let recorded_status = event.status;
    if let (Some(status), Some(quarantine)) = (recorded_status, quarantine) {
        event.status = Some(quarantine.status(status));
    }
    let importance = lifecycle_event_importance(&event);
    let key = ordinal_key(envelope.item_id, RunCellRoleV1::LifecycleEvent, ordinals);
    let cell = cell(
        key,
        importance,
        RunPresentationPayloadV1::LifecycleEvent(event),
    );
    match (recorded_status, quarantine) {
        (Some(status @ (RunItemStatus::Completed | RunItemStatus::Skipped)), Some(quarantine)) => {
            quarantine.qualify(cell, status)
        }
        _ => cell,
    }
}

fn lifecycle_event_importance(event: &LifecycleEventPresentationV1) -> RunCellImportanceV1 {
    use LifecycleEventKindV1::*;
    if matches!(event.kind, ToolRequested | ModelStarted | ModelFinished)
        || event.status == Some(RunItemStatus::Pending)
    {
        RunCellImportanceV1::Detail
    } else {
        RunCellImportanceV1::Essential
    }
}

fn progress_cell(
    envelope: &RunItemEnvelopeV1,
    message: &SafeText,
    completed: Option<u64>,
    total: Option<u64>,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> RunPresentationCellV1 {
    let key = ordinal_key(envelope.item_id, RunCellRoleV1::Progress, ordinals);
    cell(
        key,
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::Progress(ProgressPresentationV1 {
            call_id: envelope.call_id,
            message: message.clone(),
            completed,
            total,
            occurred_at_ms: envelope.occurred_at_ms,
        }),
    )
}

fn reasoning_cell(
    envelope: &RunItemEnvelopeV1,
    text: &SafeText,
    redaction_policy_version: u16,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> RunPresentationCellV1 {
    let key = ordinal_key(envelope.item_id, RunCellRoleV1::SafeReasoning, ordinals);
    cell(
        key,
        RunCellImportanceV1::Detail,
        RunPresentationPayloadV1::SafeReasoning(SafeReasoningPresentationV1 {
            text: text.clone(),
            redaction_policy_version,
            occurred_at_ms: envelope.occurred_at_ms,
        }),
    )
}

fn diagnostic_cell(
    envelope: &RunItemEnvelopeV1,
    level: &DiagnosticLevel,
    message: &SafeText,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> RunPresentationCellV1 {
    let key = ordinal_key(envelope.item_id, RunCellRoleV1::Diagnostic, ordinals);
    cell(
        key,
        RunCellImportanceV1::Diagnostic,
        RunPresentationPayloadV1::Diagnostic(DiagnosticPresentationV1 {
            level: level.clone(),
            message: message.clone(),
            occurred_at_ms: envelope.occurred_at_ms,
        }),
    )
}

fn disclosure_cell(
    envelope: &RunItemEnvelopeV1,
    progress_item_id: RunItemId,
    omitted_count: u64,
    ordinals: &mut BTreeMap<(RunItemId, RunCellRoleV1), u64>,
) -> RunPresentationCellV1 {
    let key = ordinal_key(
        envelope.item_id,
        RunCellRoleV1::ProgressDisclosure,
        ordinals,
    );
    let mut disclosure = cell(
        key,
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::ProgressDisclosure(ProgressDisclosurePresentationV1 {
            progress_item_id,
            omitted_count,
        }),
    );
    disclosure.disclosure = Some(progress_disclosure(omitted_count));
    disclosure
}

fn progress_disclosure(omitted_count: u64) -> RunCellDisclosureV1 {
    RunCellDisclosureV1 {
        reason: SafeText::operator_visible("progress updates were coalesced at persistence"),
        omitted_count: Some(omitted_count),
        inspect_action: None,
    }
}
