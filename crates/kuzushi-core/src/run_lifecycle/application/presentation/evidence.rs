use super::hydration::RunResultHydrationV1;
use super::*;

pub(super) fn evidence_cells(
    projection: &RunProjection,
    hydration: &RunPresentationHydrationV1,
) -> Vec<RunPresentationCellV1> {
    let mut cells = Vec::new();
    let mut digest_counts = BTreeMap::<SafeText, u64>::new();
    append_hydrated_results(&mut cells, projection, hydration, &mut digest_counts);
    for envelope in &projection.timeline {
        append_evidence_item(&mut cells, envelope, &mut digest_counts);
    }
    cells
}

fn append_evidence_item(
    cells: &mut Vec<RunPresentationCellV1>,
    envelope: &RunItemEnvelopeV1,
    digest_counts: &mut BTreeMap<SafeText, u64>,
) {
    match &envelope.item {
        RunItemV1::ArtifactProduced { artifact } => {
            let ordinal = next_ordinal(digest_counts, artifact.digest.clone());
            cells.push(cell(
                RunCellKey::artifact(artifact.digest.clone(), ordinal),
                RunCellImportanceV1::Essential,
                RunPresentationPayloadV1::Artifact(artifact.clone()),
            ));
        }
        RunItemV1::FindingDelta { delta } => cells.push(cell(
            RunCellKey::item(envelope.item_id, RunCellRoleV1::FindingDelta, 0),
            RunCellImportanceV1::Essential,
            RunPresentationPayloadV1::FindingDelta(delta.clone()),
        )),
        _ => {}
    }
}

fn append_hydrated_results(
    cells: &mut Vec<RunPresentationCellV1>,
    projection: &RunProjection,
    hydration: &RunPresentationHydrationV1,
    digest_counts: &mut BTreeMap<SafeText, u64>,
) {
    for call_id in &projection.call_order {
        let Some(call) = projection.calls.get(call_id) else {
            continue;
        };
        append_hydrated_call_result(cells, call, projection, hydration, digest_counts);
    }
}

fn append_hydrated_call_result(
    cells: &mut Vec<RunPresentationCellV1>,
    call: &super::super::CallProjection,
    projection: &RunProjection,
    hydration: &RunPresentationHydrationV1,
    digest_counts: &mut BTreeMap<SafeText, u64>,
) {
    let Some(reference) = call.result_artifact.as_ref() else {
        return;
    };
    let Some(result) = hydration.results.get(&call.item_id) else {
        return;
    };
    let ordinal = next_ordinal(digest_counts, reference.digest.clone());
    cells.push(hydrated_result_cell(
        reference,
        result,
        ordinal,
        projection.run_id.as_ref(),
    ));
}

fn hydrated_result_cell(
    reference: &ArtifactReference,
    result: &RunResultHydrationV1,
    ordinal: u64,
    run_id: Option<&RunId>,
) -> RunPresentationCellV1 {
    let key = RunCellKey::artifact_role(
        reference.digest.clone(),
        RunCellRoleV1::ResultSummary,
        ordinal,
    );
    match result {
        RunResultHydrationV1::Verified(summary) => verified_result_cell(key, summary, run_id),
        RunResultHydrationV1::Unavailable(detail) => cell(
            key,
            RunCellImportanceV1::Diagnostic,
            RunPresentationPayloadV1::ResultHydrationIssue(ResultHydrationIssuePresentationV1 {
                detail: detail.clone(),
            }),
        ),
    }
}

fn verified_result_cell(
    key: RunCellKey,
    summary: &crate::run_artifacts::RunResultSummary,
    run_id: Option<&RunId>,
) -> RunPresentationCellV1 {
    let result = result_summary_presentation(summary);
    let omitted_count = result.omitted_count();
    let mut result_cell = cell(
        key,
        RunCellImportanceV1::Essential,
        RunPresentationPayloadV1::ResultSummary(result),
    );
    result_cell.disclosure = result_disclosure(omitted_count, run_id);
    result_cell
}

fn result_disclosure(omitted_count: u64, run_id: Option<&RunId>) -> Option<RunCellDisclosureV1> {
    (omitted_count > 0).then(|| RunCellDisclosureV1 {
        reason: SafeText::operator_visible("bounded result detail omitted"),
        omitted_count: Some(omitted_count),
        inspect_action: run_id
            .cloned()
            .map(|run_id| WorkflowContinuation::InspectRun {
                run_id,
                reason: SafeText::operator_visible("inspect the verified result artifact"),
            }),
    })
}

fn result_summary_presentation(
    summary: &crate::run_artifacts::RunResultSummary,
) -> ResultSummaryPresentationV1 {
    ResultSummaryPresentationV1 {
        tool: SafeText::operator_visible(&summary.tool),
        status: SafeText::operator_visible(&summary.status),
        summary: SafeText::operator_visible(&summary.summary),
        output_lines: safe_lines(&summary.output_lines),
        output_line_count: summary.output_line_count,
        warnings: safe_lines(&summary.warnings),
        warning_count: summary.warning_count,
        errors: safe_lines(&summary.errors),
        error_count: summary.error_count,
        artifacts: summary
            .artifacts
            .iter()
            .map(result_artifact_presentation)
            .collect(),
        artifact_count: summary.artifact_count,
    }
}

fn safe_lines(lines: &[String]) -> Vec<SafeText> {
    lines.iter().map(SafeText::preview_line).collect()
}

fn result_artifact_presentation(
    artifact: &crate::run_artifacts::RunArtifact,
) -> ResultArtifactPresentationV1 {
    ResultArtifactPresentationV1 {
        label: SafeText::operator_visible(&artifact.label),
        path: SafeText::operator_visible(&artifact.path),
        kind: SafeText::operator_visible(&artifact.kind),
    }
}
