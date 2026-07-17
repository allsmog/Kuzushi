use super::*;

pub(super) fn timeline_cells(projection: &RunProjection) -> Vec<RunPresentationCellV1> {
    let mut ordinals = BTreeMap::<(RunItemId, RunCellRoleV1), u64>::new();
    projection
        .timeline
        .iter()
        .filter_map(|envelope| timeline_cell(envelope, &mut ordinals))
        .collect()
}

fn timeline_cell(
    envelope: &RunItemEnvelopeV1,
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
        _ => None,
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
        RunCellImportanceV1::Detail,
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
