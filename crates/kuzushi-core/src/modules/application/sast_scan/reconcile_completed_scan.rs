//! Recheck observation gaps once the completed Scan coverage receipt is durable.
use crate::findings::FindingStore;
use crate::run_artifacts::{PhaseStageOutcome, ScanStageData};
use anyhow::{Context, Result};

pub(super) fn after_receipt(
    store: &FindingStore,
    run_id: &str,
    outcome: PhaseStageOutcome,
    scan: &ScanStageData,
) -> Result<()> {
    store
        .reconcile_completed_scan_coverage(run_id, outcome, scan)
        .context("Scan coverage was saved but observation gaps could not be recorded")?;
    Ok(())
}

#[cfg(test)]
mod tests;
