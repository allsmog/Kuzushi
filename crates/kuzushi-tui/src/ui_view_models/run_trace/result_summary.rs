use super::replay_reading::saved_result_has_trusted_receipt;
use super::{failure_summary, failure_summary_available, ReplayModel};
use kuzushi_core::run_lifecycle::*;

pub(crate) fn replay_summary_available(model: &ReplayModel) -> bool {
    failure_summary_available(model) || single_result_source(model).is_some()
}

pub(crate) fn replay_document_available(model: &ReplayModel) -> bool {
    single_result_source(model).is_some()
}

pub(crate) fn replay_summary(model: &ReplayModel) -> Option<RunPresentationV1> {
    if let Some(summary) = failure_summary(model) {
        return Some(summary);
    }
    let source = single_result_source(model)?;
    let mut summary = source.clone();
    summary.timeline.clear();
    summary.summary.retain(|section| {
        matches!(
            section.kind,
            RunPresentationSectionKindV1::Attention | RunPresentationSectionKindV1::Evidence
        )
    });
    for section in &mut summary.summary {
        section.cells = section.cells.iter().filter_map(reading_cell).collect();
    }
    Some(summary)
}

fn single_result_source(model: &ReplayModel) -> Option<&RunPresentationV1> {
    if !result_model_is_available(model) {
        return None;
    }
    let source = model.presentation.as_ref()?;
    (eligible_result(source) && has_single_matching_result(source)).then_some(source)
}

fn result_model_is_available(model: &ReplayModel) -> bool {
    !model.metadata_missing && model.projection_error.is_none() && model.single_result_work
}

fn eligible_result(source: &RunPresentationV1) -> bool {
    source.source == RunProjectionSource::TypedV1
        && saved_result_has_trusted_receipt(source)
        && !has_unavailable_evidence(source)
}

fn has_unavailable_evidence(source: &RunPresentationV1) -> bool {
    source
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .any(|cell| {
            matches!(
                cell.payload,
                RunPresentationPayloadV1::ResultHydrationIssue(_)
            )
        })
}

fn has_single_matching_result(source: &RunPresentationV1) -> bool {
    let mut results = source
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .filter_map(|cell| match &cell.payload {
            RunPresentationPayloadV1::ResultSummary(result) => Some(result),
            _ => None,
        });
    let Some(result) = results.next() else {
        return false;
    };
    results.next().is_none() && result_matches_terminal(result, source.terminal_status)
}

fn result_matches_terminal(
    result: &ResultSummaryPresentationV1,
    terminal: Option<RunItemStatus>,
) -> bool {
    result.output_line_count > 0
        && Some(result.status.as_str()) == terminal.map(|status| status.label())
}

fn reading_cell(source: &RunPresentationCellV1) -> Option<RunPresentationCellV1> {
    if matches!(source.payload, RunPresentationPayloadV1::Artifact(_)) {
        return None;
    }
    let mut cell = source.clone();
    if let RunPresentationPayloadV1::ResultSummary(result) = &mut cell.payload {
        result.artifacts.clear();
        result.artifact_count = 0;
    }
    Some(cell)
}

#[cfg(test)]
mod tests;
