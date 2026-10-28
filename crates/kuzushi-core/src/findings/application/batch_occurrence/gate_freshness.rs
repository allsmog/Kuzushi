use super::{load, BatchOccurrenceReport, BatchReceiptPending};
use crate::capabilities::campaign::{ScanBatchGateBinding, ScanBatchGateOutcome};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

pub(super) fn validate(
    root: &Path,
    plan: &Value,
    report: &BatchOccurrenceReport,
    outcome: &ScanBatchGateOutcome,
    current: (ScanBatchGateBinding, usize),
) -> Result<()> {
    let (binding, blocking_count) = current;
    if outcome.binding == binding && outcome.blocking_safe_fold_count == blocking_count {
        return Ok(());
    }
    if queued_trials_changed(root, plan, report)? {
        return Err(BatchReceiptPending.into());
    }
    if crate::capabilities::campaign::batch_controller_owns_publication(root, &report.batch_id)? {
        return Err(BatchReceiptPending.into());
    }
    anyhow::bail!("batch gate is stale for the current trial/finding/SARIF state")
}

fn queued_trials_changed(
    root: &Path,
    plan: &Value,
    report: &BatchOccurrenceReport,
) -> Result<bool> {
    let queue = load::read_optional_batch_document(root, &report.batch_id, "queue.json")?;
    let current = load::trial_reports(plan, queue.as_ref());
    let mut previous = report.trials.clone();
    // Child finding references are hydrated from separate authenticated artifacts.
    // Compare only the queue projection to establish that this read crossed an update.
    for trial in &mut previous {
        trial.finding_run_ids.clear();
    }
    Ok(current != previous)
}

#[cfg(test)]
mod tests;
