//! Retained attempt outcomes stay distinct from the current fixed job states.
use kuzushi_core::run_artifacts::{PhaseStageOutcome, PhaseStageReceipt};
use kuzushi_core::workspace::InvestigationAttemptReceipt;
use std::collections::BTreeMap;

pub(super) fn insert_after_scope(
    content: &mut Vec<String>,
    attempts: &[InvestigationAttemptReceipt],
    details: bool,
) {
    let position = content
        .iter()
        .position(|line| line.starts_with("Scope: "))
        .map_or(0, |index| index + 1);
    content.splice(position..position, lines(attempts, details));
}

fn lines(attempts: &[InvestigationAttemptReceipt], details: bool) -> Vec<String> {
    if attempts.is_empty() {
        return Vec::new();
    }
    let summary = outcome_counts(attempts)
        .into_iter()
        .map(|(outcome, count)| format!("{count} {outcome}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut lines = vec![format!("Recorded attempts: {} · {summary}", attempts.len())];
    if details {
        lines.extend(attempts.iter().map(attempt_line));
    }
    lines
}

fn outcome_counts(attempts: &[InvestigationAttemptReceipt]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for attempt in attempts {
        *counts.entry(outcome_label(attempt)).or_insert(0) += 1;
    }
    counts
}

fn outcome_label(attempt: &InvestigationAttemptReceipt) -> &'static str {
    attempt
        .scan
        .as_ref()
        .map_or("outcome unavailable", scan_outcome_label)
}

fn scan_outcome_label(receipt: &PhaseStageReceipt) -> &'static str {
    match receipt.outcome {
        PhaseStageOutcome::Completed => "completed",
        PhaseStageOutcome::Partial => "partial",
        PhaseStageOutcome::Failed => "failed",
        PhaseStageOutcome::Skipped => "skipped",
    }
}

fn attempt_line(attempt: &InvestigationAttemptReceipt) -> String {
    format!("Attempt: {} · {}", attempt.run_id, outcome_label(attempt))
}

#[cfg(test)]
mod tests;
