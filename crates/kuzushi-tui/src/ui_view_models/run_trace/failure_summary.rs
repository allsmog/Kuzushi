use super::{replay_can_lead_with_results, ReplayIssueModel, ReplayModel};
use kuzushi_core::run_lifecycle::*;

pub(crate) fn failure_summary_available(model: &ReplayModel) -> bool {
    model.issue.is_some()
        && model
            .presentation
            .as_ref()
            .is_some_and(replay_can_lead_with_results)
}

pub(crate) fn failure_summary(model: &ReplayModel) -> Option<RunPresentationV1> {
    if !failure_summary_available(model) {
        return None;
    }
    let source = model.presentation.as_ref()?;
    let issue = model.issue.as_ref()?;
    Some(RunPresentationV1 {
        run_id: source.run_id.clone(),
        source: source.source.clone(),
        health: source.health.clone(),
        summary: summary_sections(source, issue),
        timeline: Vec::new(),
        terminal_status: source.terminal_status,
    })
}

fn summary_sections(
    source: &RunPresentationV1,
    issue: &ReplayIssueModel,
) -> Vec<RunPresentationSectionV1> {
    source
        .summary
        .iter()
        .filter(|section| {
            matches!(
                section.kind,
                RunPresentationSectionKindV1::Attention | RunPresentationSectionKindV1::Evidence
            )
        })
        .map(|section| RunPresentationSectionV1 {
            kind: section.kind.clone(),
            cells: section
                .cells
                .iter()
                .filter_map(|cell| summary_cell(cell, issue))
                .collect(),
        })
        .collect()
}

fn summary_cell(
    source: &RunPresentationCellV1,
    issue: &ReplayIssueModel,
) -> Option<RunPresentationCellV1> {
    if matches!(source.payload, RunPresentationPayloadV1::Artifact(_)) {
        return None;
    }
    let mut cell = source.clone();
    if let RunPresentationPayloadV1::ResultSummary(result) = &mut cell.payload {
        result.artifacts.clear();
        result.artifact_count = 0;
        if issue.source_key.as_ref() == Some(&source.key) {
            fold_primary_issue(result, issue);
        }
    }
    Some(cell)
}

fn fold_primary_issue(result: &mut ResultSummaryPresentationV1, issue: &ReplayIssueModel) {
    let distinct = |text: &SafeText| text.as_str().trim() != issue.message.trim();
    result.output_lines.retain(distinct);
    result.errors.retain(distinct);
    result.warnings.retain(distinct);
    if result.summary.as_str().trim() == issue.message.trim() {
        result.summary = SafeText::operator_visible("Recorded issue shown above.");
    }
}

#[cfg(test)]
mod tests;
