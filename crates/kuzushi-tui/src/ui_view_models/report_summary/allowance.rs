//! The viewed report owns its allowance; workspace history has no single ceiling.
use super::{report_document_view, ReportReadView, ShellApp};
use kuzushi_core::workspace::InvestigationReportDocument;
use std::sync::Arc;

pub(crate) fn report_allowance_calls(app: &ShellApp) -> Option<String> {
    if !selected_report_scope(app) {
        return None;
    }
    match report_document_view(app) {
        ReportReadView::Ready(document) => document_calls(&document),
        ReportReadView::Refreshing(document) => {
            document_calls(&document).map(|calls| format!("previous {calls}"))
        }
        state => unready_calls(state, app.router.report().study().is_some()),
    }
}

fn selected_report_scope(app: &ShellApp) -> bool {
    app.shell_view() == crate::ShellView::Report
        && app.target().is_some()
        && !app.router.report().workspace_history()
}

fn document_calls(document: &InvestigationReportDocument) -> Option<String> {
    let current = &document.summary().allowance?.current_investigation;
    Some(super::super::investigation_allowance::calls_label(current))
}

fn unready_calls(
    state: ReportReadView<Arc<InvestigationReportDocument>>,
    explicit_study: bool,
) -> Option<String> {
    match state {
        ReportReadView::Empty => explicit_study.then(|| "calls unavailable".into()),
        ReportReadView::Failed(_) => Some("calls unavailable".into()),
        _ => Some("calls loading".into()),
    }
}
