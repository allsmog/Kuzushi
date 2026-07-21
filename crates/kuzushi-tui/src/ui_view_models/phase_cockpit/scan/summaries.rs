use super::attempt::{engine_outcome, engine_outcome_from_attempt};
use crate::ui_view_models::ScanEngineOutcomeModel;
use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
use kuzushi_core::{RunSummary, RunSummaryEntry, RunSummaryEntryState, WorkflowPhase};
use std::collections::BTreeSet;

pub(super) fn terminal_scan_summary(entry: &RunSummaryEntry) -> Option<&RunSummary> {
    let RunSummaryEntryState::Ready(summary) = &entry.state else {
        return None;
    };
    (summary_is_terminal(summary) && summary_is_scan(summary)).then_some(summary)
}

fn summary_is_terminal(summary: &RunSummary) -> bool {
    !matches!(
        summary.status.trim().to_ascii_lowercase().as_str(),
        "" | "running" | "queued" | "started"
    )
}

fn summary_is_scan(summary: &RunSummary) -> bool {
    summary.kind.eq_ignore_ascii_case("scan")
        || summary.tool.as_deref().is_some_and(|tool| {
            kuzushi_core::modules::tool_phase(tool) == Some(WorkflowPhase::Scan)
        })
}

pub(super) fn summaries_for_refs<'a>(
    entries: &'a [RunSummaryEntry],
    run_refs: &[String],
) -> Vec<&'a RunSummary> {
    run_refs
        .iter()
        .filter_map(|run_ref| {
            entries.iter().find_map(|entry| match &entry.state {
                RunSummaryEntryState::Ready(summary) if summary.run_id == *run_ref => Some(summary),
                RunSummaryEntryState::Ready(_) | RunSummaryEntryState::Issue(_) => None,
            })
        })
        .collect()
}

pub(super) fn scanner_plan(summaries: &[&RunSummary]) -> String {
    let tools = summaries
        .iter()
        .filter(|summary| summary_is_scan(summary))
        .filter_map(|summary| summary.tool.as_deref())
        .collect::<BTreeSet<_>>();
    if tools.is_empty() {
        "scanner plan referenced by attempt; tool list not recorded".to_string()
    } else {
        format!(
            "recorded tools {}",
            tools.into_iter().collect::<Vec<_>>().join(", ")
        )
    }
}

pub(super) fn scanner_outcomes(
    summaries: &[&RunSummary],
    attempt_outcome: PhaseAttemptOutcome,
) -> Vec<ScanEngineOutcomeModel> {
    let outcomes = summaries
        .iter()
        .filter(|summary| summary_is_scan(summary))
        .map(|summary| engine_outcome(summary))
        .collect::<Vec<_>>();
    if outcomes.is_empty() {
        vec![ScanEngineOutcomeModel {
            engine: "Scan attempt".to_string(),
            tool_key: None,
            outcome: engine_outcome_from_attempt(attempt_outcome).to_string(),
            run_ref: None,
            detail: None,
        }]
    } else {
        outcomes
    }
}
