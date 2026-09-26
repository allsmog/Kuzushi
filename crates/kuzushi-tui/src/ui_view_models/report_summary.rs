use super::journey::journey_reality_projection;
use crate::app::{RunSummaryEntriesState, ShellApp, ViewDataState};
use kuzushi_core::{RunSummaryEntry, RunSummaryEntryState};

pub(crate) fn report_review_summary(app: &ShellApp) -> String {
    let Some(reality) = journey_reality_projection(app) else {
        return "Select a target to report its findings.".to_string();
    };
    let progress = reality.progress;
    format!(
        "{} current findings · {} reviewed · {} actionable · {} proof-backed",
        progress.finding_total,
        progress.reviewed_findings,
        progress.confirmed_findings,
        progress.proof_backed_findings,
    )
}

/// Cost records can include parent totals and the same work's child runs.
/// Count coverage without adding overlapping amounts or inferring free work
/// from missing/zero observed metering. Hydration bounds this to recent runs.
pub(crate) fn report_cost_coverage(app: &ShellApp) -> String {
    let state = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_entries(app.target());
    match state {
        ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) => {
            cost_coverage(&entries).label()
        }
        ViewDataState::Ready(RunSummaryEntriesState::Failed(_)) => {
            "Recent run cost records could not be loaded.".to_string()
        }
        ViewDataState::NotRequested | ViewDataState::Loading => {
            "Loading recent run cost records…".to_string()
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct CostCoverage {
    complete: usize,
    incomplete: usize,
    unavailable: usize,
    invalid: usize,
}

impl CostCoverage {
    fn label(&self) -> String {
        format!(
            "Recent run cost records: {} complete · {} incomplete · {} unavailable · {} unreadable/invalid",
            self.complete, self.incomplete, self.unavailable, self.invalid,
        )
    }
}

fn cost_coverage(entries: &[RunSummaryEntry]) -> CostCoverage {
    let mut coverage = CostCoverage::default();
    for entry in entries {
        match &entry.state {
            RunSummaryEntryState::Ready(summary) => classify_cost(summary, &mut coverage),
            RunSummaryEntryState::Issue(_) => coverage.invalid += 1,
        }
    }
    coverage
}

fn classify_cost(summary: &kuzushi_core::RunSummary, coverage: &mut CostCoverage) {
    match summary.checked_cost_report() {
        Err(_) => coverage.invalid += 1,
        Ok(cost) if cost.is_complete() => coverage.complete += 1,
        Ok(cost) if cost.is_unavailable() => coverage.unavailable += 1,
        Ok(_) => coverage.incomplete += 1,
    }
}

#[cfg(test)]
mod tests;
