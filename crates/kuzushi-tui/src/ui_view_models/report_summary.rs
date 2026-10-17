use crate::app::{RunSummaryEntriesState, ShellApp, ViewDataState};
use kuzushi_core::{RunSummaryEntry, RunSummaryEntryState};
use std::sync::Arc;

mod read_state;
pub(super) use read_state::{report_document_view, report_workspace_review_view};
pub(crate) use read_state::{report_is_refreshing, ReportReadView};

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

mod review;
pub(crate) use review::{report_review_footer_summary, report_review_summary};

pub(crate) fn report_investigation_state(
    app: &ShellApp,
) -> ViewDataState<Result<Option<Arc<kuzushi_core::workspace::InvestigationReportDocument>>, String>>
{
    app.workbench_cache()
        .borrow()
        .cached_selected_report(app.target(), &app.report_hydration_key())
}

pub(crate) fn report_workspace_review_state(
    app: &ShellApp,
) -> ViewDataState<Result<Arc<kuzushi_core::workspace::WorkspaceReviewSummary>, String>> {
    let Some(target) = app.target() else {
        return ViewDataState::NotRequested;
    };
    let key = crate::app::ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: app.findings_read_watermark(),
    };
    app.workbench_cache()
        .borrow()
        .cached_workspace_report_review(target, &key)
}

pub(crate) fn report_export_campaign(app: &ShellApp) -> Result<Option<String>, String> {
    if app.router.report().workspace_history() {
        return workspace_export_ready(app);
    }
    match report_investigation_state(app) {
        ViewDataState::Ready(Ok(None)) if app.router.report().study().is_none() => workspace_export_ready(app),
        ViewDataState::Ready(Ok(receipt)) => selected_export_campaign(receipt, app.router.report().study().is_some()),
        ViewDataState::Ready(Err(error)) => Err(format!("Study receipt unavailable: {error}. Press s to explicitly export workspace history instead.")),
        _ => Err("Study receipt is loading. Wait before exporting, or press s for workspace history.".into()),
    }
}

fn selected_export_campaign(
    document: Option<Arc<kuzushi_core::workspace::InvestigationReportDocument>>,
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

fn workspace_export_ready(app: &ShellApp) -> Result<Option<String>, String> {
    match report_workspace_review_state(app) {
        ViewDataState::Ready(Ok(_)) => Ok(None),
        ViewDataState::Ready(Err(error)) => Err(format!(
            "Report decisions unavailable: {error}. Press r to refresh before exporting."
        )),
        _ => Err("Report is refreshing. Wait for current decisions before exporting.".into()),
    }
}

pub(crate) fn report_action_error(app: &ShellApp) -> Option<String> {
    let route = app.router.report();
    if route.export_read_error() {
        return report_export_campaign(app).err();
    }
    route.reveal_error().map(str::to_string)
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
