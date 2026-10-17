//! Previous reads are a labeled presentation state, never export authorization.
use super::*;
use kuzushi_core::workspace::{InvestigationReportDocument, WorkspaceReviewSummary};

pub(crate) enum ReportReadView<T> {
    Ready(T),
    Refreshing(T),
    Empty,
    Loading,
    Failed(String),
}

impl<T> ReportReadView<T> {
    fn from_pending(previous: Option<T>) -> Self {
        previous.map(Self::Refreshing).unwrap_or(Self::Loading)
    }

    fn is_refreshing(&self) -> bool {
        matches!(self, Self::Refreshing(_))
    }
}

pub(crate) fn report_document_view(
    app: &ShellApp,
) -> ReportReadView<Arc<InvestigationReportDocument>> {
    match report_investigation_state(app) {
        ViewDataState::Ready(Ok(Some(document))) => ReportReadView::Ready(document),
        ViewDataState::Ready(Ok(None)) => ReportReadView::Empty,
        ViewDataState::Ready(Err(error)) => ReportReadView::Failed(error),
        _ => ReportReadView::from_pending(previous_document(app)),
    }
}

fn previous_document(app: &ShellApp) -> Option<Arc<InvestigationReportDocument>> {
    app.workbench_cache()
        .borrow()
        .cached_previous_selected_report(app.target()?, &app.report_hydration_key())
}

pub(crate) fn report_workspace_review_view(
    app: &ShellApp,
) -> ReportReadView<Arc<WorkspaceReviewSummary>> {
    match report_workspace_review_state(app) {
        ViewDataState::Ready(Ok(summary)) => ReportReadView::Ready(summary),
        ViewDataState::Ready(Err(error)) => ReportReadView::Failed(error),
        _ => ReportReadView::from_pending(previous_workspace_review(app)),
    }
}

fn previous_workspace_review(app: &ShellApp) -> Option<Arc<WorkspaceReviewSummary>> {
    let key = crate::app::ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: app.findings_read_watermark(),
    };
    app.workbench_cache()
        .borrow()
        .cached_previous_workspace_report_review(app.target()?, &key)
}

pub(crate) fn report_is_refreshing(app: &ShellApp) -> bool {
    if app.router.report().workspace_history() {
        return report_workspace_review_view(app).is_refreshing();
    }
    match report_document_view(app) {
        ReportReadView::Empty if app.router.report().study().is_none() => {
            report_workspace_review_view(app).is_refreshing()
        }
        state => state.is_refreshing(),
    }
}

#[cfg(test)]
mod tests;
