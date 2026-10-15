use super::journey::journey_reality_projection;
use crate::app::{RunSummaryEntriesState, ShellApp, ViewDataState};
use kuzushi_core::{RunSummaryEntry, RunSummaryEntryState};

pub(crate) fn report_source_history_coverage(
    format: kuzushi_core::WorkspaceExportFormat,
) -> &'static str {
    let omitted = kuzushi_core::workspace::workspace_export_omitted_fields(format);
    if omitted
        .iter()
        .any(|field| matches!(*field, "provenance" | "provenance.sourceHistory"))
    {
        "Recorded source summaries: omitted in this format."
    } else {
        "Recorded source summaries: included with dates and run endpoints."
    }
}

pub(crate) fn report_review_summary(app: &ShellApp) -> String {
    if !app.router.report().workspace_history() {
        if let Some(summary) = study_review_summary(app) {
            return summary;
        }
    }
    let Some(reality) = journey_reality_projection(app) else {
        return "Select a target to report its findings.".to_string();
    };
    let progress = reality.progress;
    format!(
        "{} {} · {} reviewed · {} confirmed",
        progress.finding_total,
        super::finding_summary::finding_noun(progress.finding_total),
        progress.reviewed_findings,
        progress.confirmed_findings,
    )
}

fn study_review_summary(app: &ShellApp) -> Option<String> {
    match report_investigation_state(app) {
        ViewDataState::Ready(Ok(document)) => loaded_review_summary(app, document),
        ViewDataState::Ready(Err(_)) => {
            Some("Study findings and decisions could not be loaded.".into())
        }
        _ => Some("Loading study findings and decisions…".into()),
    }
}

fn loaded_review_summary(
    app: &ShellApp,
    document: Option<kuzushi_core::workspace::InvestigationReportDocument>,
) -> Option<String> {
    if let Some(document) = document {
        let receipt = document.summary();
        return Some(format!(
            "{} {} · {} reviewed · {} confirmed",
            receipt.finding_count,
            super::finding_summary::finding_noun(receipt.finding_count),
            receipt.reviewed_count,
            receipt.confirmed_count
        ));
    }
    app.router
        .report()
        .study()
        .map(|_| "Selected study findings and decisions are unavailable.".into())
}

pub(crate) fn report_investigation_state(
    app: &ShellApp,
) -> ViewDataState<Result<Option<kuzushi_core::workspace::InvestigationReportDocument>, String>> {
    app.workbench_cache()
        .borrow()
        .cached_selected_report(app.target(), &app.report_hydration_key())
}

pub(crate) fn report_export_campaign(app: &ShellApp) -> Result<Option<String>, String> {
    if app.router.report().workspace_history() {
        return Ok(None);
    }
    match report_investigation_state(app) {
        ViewDataState::Ready(Ok(receipt)) => selected_export_campaign(receipt, app.router.report().study().is_some()),
        ViewDataState::Ready(Err(error)) => Err(format!("Study receipt unavailable: {error}. Press s to explicitly export workspace history instead.")),
        _ => Err("Study receipt is loading. Wait before exporting, or press s for workspace history.".into()),
    }
}

fn selected_export_campaign(
    document: Option<kuzushi_core::workspace::InvestigationReportDocument>,
    explicit: bool,
) -> Result<Option<String>, String> {
    if let Some(document) = document {
        return Ok(Some(document.summary().campaign_id.to_owned()));
    }
    if explicit {
        return Err("Selected study receipt is unavailable. Reopen it, or press s to explicitly export workspace history.".into());
    }
    Ok(None)
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
    missing_metadata: usize,
    invalid: usize,
}

impl CostCoverage {
    fn label(&self) -> String {
        let mut counts = vec![
            format!("{} complete", self.complete),
            format!("{} incomplete", self.incomplete),
            format!("{} unavailable", self.unavailable),
        ];
        if self.missing_metadata > 0 {
            counts.push(format!("{} missing metadata", self.missing_metadata));
        }
        if self.invalid > 0 {
            counts.push(format!("{} unreadable/invalid", self.invalid));
        }
        format!("Recent run cost records: {}", counts.join(" · "))
    }
}

fn cost_coverage(entries: &[RunSummaryEntry]) -> CostCoverage {
    let mut coverage = CostCoverage::default();
    for entry in entries {
        match &entry.state {
            RunSummaryEntryState::Ready(summary) => classify_cost(summary, &mut coverage),
            RunSummaryEntryState::Issue(kuzushi_core::RunSummaryIssue::MissingMetadata) => {
                coverage.missing_metadata += 1;
            }
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
