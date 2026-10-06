//! Bounded historical choices; detailed usage is read only for a named run.
use super::*;
use crate::run_artifacts::{load_run_summary_without_repair, RunSummaryEntryState};

pub const SCAN_USAGE_HISTORY_LIMIT: usize = 100;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanUsageCatalogue {
    pub run_ids: Vec<String>,
    pub inspected_entries: usize,
    pub history_limit_reached: bool,
}

pub fn load_scan_usage_catalogue(
    root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<ScanUsageCatalogue>> {
    if cancelled() {
        return Ok(None);
    }
    let entries =
        crate::run_artifacts::list_recent_run_summary_entries(root, SCAN_USAGE_HISTORY_LIMIT + 1)?;
    let mut catalogue = ScanUsageCatalogue {
        history_limit_reached: entries.len() > SCAN_USAGE_HISTORY_LIMIT,
        ..Default::default()
    };
    for entry in entries.into_iter().take(SCAN_USAGE_HISTORY_LIMIT) {
        if cancelled() {
            return Ok(None);
        }
        catalogue.inspected_entries += 1;
        append_completed_scan(&mut catalogue, entry.state);
    }
    Ok(Some(catalogue))
}

pub fn load_named_scan_usage(root: &Path, run: &str) -> Result<ScanResourceEvidence> {
    let summary = load_run_summary_without_repair(root, run)?;
    anyhow::ensure!(
        summary.run_id == run,
        "historical scan metadata names a different run"
    );
    load_scan_resource_evidence(root, &summary)
}

fn completed_scan(summary: &RunSummary) -> bool {
    summary.status == "completed" && summary.tool.as_deref() == Some("sast:scan")
}

fn append_completed_scan(catalogue: &mut ScanUsageCatalogue, state: RunSummaryEntryState) {
    let RunSummaryEntryState::Ready(summary) = state else {
        return;
    };
    if completed_scan(&summary) {
        catalogue.run_ids.push(summary.run_id);
    }
}

#[cfg(test)]
mod tests;
