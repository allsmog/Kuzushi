use super::{report_document_view, report_workspace_review_view, ReportReadView};
use crate::app::{ShellApp, ViewDataState};
use kuzushi_core::findings::ReviewDecisionCounts;

#[derive(Debug, Clone, Copy)]
struct ReportReviewCounts {
    findings: usize,
    decisions: ReviewDecisionCounts,
    reassessment_required: usize,
}

enum ReportReviewState {
    Ready(ReportReviewCounts),
    Refreshing(ReportReviewCounts),
    Loading,
    Unavailable,
    NoTarget,
}

pub(crate) fn report_review_summary(app: &ShellApp) -> String {
    match report_review_state(app) {
        ReportReviewState::Ready(counts) => review_decision_totals(counts),
        ReportReviewState::Refreshing(counts) => {
            format!("{} · previous read", review_decision_totals(counts))
        }
        ReportReviewState::Loading => "Loading report findings and decisions…".into(),
        ReportReviewState::Unavailable => {
            "Report decisions unavailable. Press r to refresh the source comparison.".into()
        }
        ReportReviewState::NoTarget => "Select a target to report its findings.".into(),
    }
}

pub(crate) fn report_review_footer_summary(app: &ShellApp) -> String {
    match report_review_state(app) {
        ReportReviewState::Ready(counts) => review_footer_totals(counts),
        ReportReviewState::Refreshing(counts) => {
            format!("{} · previous read", review_footer_totals(counts))
        }
        ReportReviewState::Loading => "Report loading".into(),
        ReportReviewState::Unavailable => "Report unavailable".into(),
        ReportReviewState::NoTarget => "No report target".into(),
    }
}

fn report_review_state(app: &ShellApp) -> ReportReviewState {
    if app.target().is_none() {
        return ReportReviewState::NoTarget;
    }
    if app.router.report().workspace_history() {
        return workspace_review_state(app);
    }
    match report_document_view(app) {
        ReportReadView::Ready(document) => ReportReviewState::Ready(document_counts(&document)),
        ReportReadView::Refreshing(document) => {
            ReportReviewState::Refreshing(document_counts(&document))
        }
        ReportReadView::Empty => missing_study_state(app),
        ReportReadView::Failed(_) => ReportReviewState::Unavailable,
        _ => ReportReviewState::Loading,
    }
}

fn document_counts(
    document: &kuzushi_core::workspace::InvestigationReportDocument,
) -> ReportReviewCounts {
    let summary = document.summary();
    ReportReviewCounts {
        findings: summary.finding_count,
        decisions: summary.review_decision_counts,
        reassessment_required: summary.reassessment_required_count,
    }
}

fn missing_study_state(app: &ShellApp) -> ReportReviewState {
    if app.router.report().study().is_some() {
        return ReportReviewState::Unavailable;
    }
    workspace_review_state(app)
}

fn workspace_review_state(app: &ShellApp) -> ReportReviewState {
    match report_workspace_review_view(app) {
        ReportReadView::Ready(summary) => ReportReviewState::Ready(workspace_counts(&summary)),
        ReportReadView::Refreshing(summary) => {
            ReportReviewState::Refreshing(workspace_counts(&summary))
        }
        ReportReadView::Failed(_) => ReportReviewState::Unavailable,
        _ => ReportReviewState::Loading,
    }
}

fn workspace_counts(
    summary: &kuzushi_core::workspace::WorkspaceReviewSummary,
) -> ReportReviewCounts {
    ReportReviewCounts {
        findings: summary.finding_count,
        decisions: summary.decisions,
        reassessment_required: summary.reassessment_required,
    }
}

fn review_decision_totals(counts: ReportReviewCounts) -> String {
    let mut parts = vec![
        format!(
            "{} {}",
            counts.findings,
            crate::ui_view_models::finding_summary::finding_noun(counts.findings)
        ),
        format!("{} pending", pending_count(counts)),
        format!("TP: {}", counts.decisions.confirmed_total()),
        format!("FP: {}", counts.decisions.rejected_false_positive),
    ];
    parts.extend(other_review_totals(counts.decisions));
    if counts.reassessment_required > 0 {
        parts.push(format!(
            "source review needed: {}",
            counts.reassessment_required
        ));
    }
    parts.join(" · ")
}

fn review_footer_totals(counts: ReportReviewCounts) -> String {
    let mut parts = vec![format!("{} pending", pending_count(counts))];
    parts.extend(nonzero_counts(&[
        (counts.decisions.confirmed_total(), "TP"),
        (counts.decisions.rejected_false_positive, "FP"),
    ]));
    parts.extend(other_review_totals(counts.decisions));
    if counts.reassessment_required > 0 {
        parts.push(format!("{} source review", counts.reassessment_required));
    }
    parts.join(" · ")
}

fn pending_count(counts: ReportReviewCounts) -> usize {
    counts.findings.saturating_sub(counts.decisions.total())
}

fn other_review_totals(counts: ReviewDecisionCounts) -> Vec<String> {
    nonzero_counts(&[
        (counts.deferred, "deferred"),
        (counts.accepted_risk, "accepted risk"),
        (counts.suppressed, "suppressed"),
    ])
}

fn nonzero_counts(counts: &[(usize, &str)]) -> Vec<String> {
    counts
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, label)| format!("{count} {label}"))
        .collect()
}

#[cfg(test)]
mod tests;
