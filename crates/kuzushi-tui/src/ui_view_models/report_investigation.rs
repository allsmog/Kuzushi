use super::report_summary::report_investigation_state;
use crate::app::{ShellApp, ViewDataState};
use kuzushi_core::workspace::InvestigationReportReceipt;

mod scan_receipt;
mod scope;

pub(crate) fn report_investigation_lines(app: &ShellApp) -> Vec<String> {
    if app.router.report().workspace_history() {
        return history_lines(app);
    }
    match report_investigation_state(app) {
        ViewDataState::Ready(Ok(Some(receipt))) => {
            let current = app
                .report_scan_attempt()
                .is_none_or(|attempt| attempt.current);
            study_lines(&receipt, app.router.report().provenance_details(), current)
        }
        ViewDataState::Ready(Ok(None)) => history_lines(app),
        ViewDataState::Ready(Err(error)) => vec![
            "Scope: study receipt unavailable".into(),
            error,
            "s selects workspace history without a study coverage claim.".into(),
        ],
        _ => vec!["Scope: loading Scan study receipt…".into()],
    }
}

fn history_lines(app: &ShellApp) -> Vec<String> {
    let mut lines = vec![
        "Scope: workspace history · all recorded source revisions".into(),
        "Finding review completeness does not describe repository coverage.".into(),
        "Workspace spend: total unavailable".into(),
    ];
    lines.extend(scan_receipt::lines(app));
    lines
}

fn study_lines(receipt: &InvestigationReportReceipt, details: bool, current: bool) -> Vec<String> {
    let work = &receipt.occurrence;
    let mut lines = vec![format!("Scope: study {} · s switches to workspace history", receipt.campaign_id),
        format!("Work: {} completed / {} planned · {} failed · {} pending", work.completed, work.planned, work.failed, work.pending),
        format!("Evidence: {} producer observations · recurrence is separate from confidence", receipt.observation_count),
        "Coverage: engine and inventory omissions are not fully recorded; no complete coverage claim.".into(),
        source_label(receipt), context_label(receipt),
        format!("Model: {} · {} worker(s)", receipt.equivalence.components.model.as_deref().unwrap_or("not recorded"), receipt.workers)];
    lines.splice(1..1, source_currency_lines(current));
    lines.extend(scope::lines(&receipt.scope, details));
    lines.extend(allowance_lines(receipt));
    if details {
        lines.extend(provenance_lines(receipt));
    }
    lines
}

/// A study selected on earlier source stays reportable, but never reads as
/// a description of the files on disk now.
fn source_currency_lines(current: bool) -> Vec<String> {
    if current {
        return Vec::new();
    }
    vec![
        "Recorded on earlier source: current files differ, so this study does not describe them."
            .into(),
    ]
}

fn source_label(receipt: &InvestigationReportReceipt) -> String {
    match &receipt.equivalence.components.target_git {
        Some(git) => format!(
            "Source: {} · {} · recorded content in p details",
            git.sha,
            if git.dirty { "dirty" } else { "clean" }
        ),
        None => "Source: unversioned · recorded content fingerprint in p details".into(),
    }
}

fn context_label(receipt: &InvestigationReportReceipt) -> String {
    match &receipt.equivalence.components.threat_model {
        Some(reference) => format!(
            "Context: frozen {} / {}",
            reference["modelId"].as_str().unwrap_or("recorded model"),
            reference["revisionId"]
                .as_str()
                .unwrap_or("recorded revision")
        ),
        None => "Context: explicitly omitted from this study".into(),
    }
}

fn allowance_lines(receipt: &InvestigationReportReceipt) -> Vec<String> {
    let Some(accounting) = &receipt.allowance else {
        return vec!["Allowance: no approval recorded for this legacy campaign".into()];
    };
    let current = &accounting.current_investigation;
    vec![format!("Shared allowance: {} committed / {} calls · {} unresolved · {} protected review remaining", current.committed_calls,
        current.limits.max_provider_calls, current.unresolved_calls, current.protected_review_remaining()),
        format!("Investigation cost: {} · includes context and other approved work", super::format_runtime_cost(current.cost, None)),
        format!("Study approval: revision {} · accounting: revision {}", accounting.approved_revision, current.revision)]
}

fn provenance_lines(receipt: &InvestigationReportReceipt) -> Vec<String> {
    let components = &receipt.equivalence.components;
    let mut lines = vec![
        format!("Plan digest: {}", receipt.plan_sha256),
        format!("Recorded content: {}", components.workspace_identity),
        format!(
            "Context reference: {}",
            components
                .threat_model
                .as_ref()
                .map_or("none".into(), ToString::to_string)
        ),
        format!("Configuration digest: {}", components.config_sha256),
        format!(
            "Prompt overrides digest: {}",
            components.prompt_overrides_sha256
        ),
    ];
    lines.extend(receipt.limitations.iter().cloned());
    lines
}

#[cfg(test)]
mod tests;
