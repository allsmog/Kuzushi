use super::report_summary::{report_document_view, report_workspace_review_view, ReportReadView};
use crate::app::{ShellApp, ViewDataState};
use kuzushi_core::workspace::InvestigationReportDocument;
use kuzushi_core::workspace::InvestigationReportReceipt;

mod attempt_history;
mod context_evidence;
mod context_guidance;
mod engine_details;
mod matrix;
mod models;
mod scan_receipt;
mod scope;
mod scopes;
use engine_details::append_document_engine_details;
#[cfg(test)]
use engine_details::{engine_detail_line, scan_detail_lines, summarize_engine_details};
use models::discovery_model_line;

pub(crate) fn report_source_notice(app: &ShellApp) -> Option<&'static str> {
    if app.router.report().workspace_history() {
        return Some("History · current source unassessed");
    }
    if app.router.report().study().is_some() {
        return Some("Recorded source · current unassessed");
    }
    app.report_scan_attempt()
        .filter(|attempt| !attempt.current)
        .map(|_| "Earlier source · reassess checkout")
}

pub(crate) fn report_investigation_lines(app: &ShellApp) -> Vec<String> {
    let mut lines = vec![authority_note(app.router.report().provenance_details()).into()];
    lines.extend(report_scope_lines(app));
    lines.push(lesson_note(app).into());
    lines
}

fn authority_note(details: bool) -> &'static str {
    if details {
        return "TP confirmed · FP false positive. Includes human and automatic review. Severity stays as reported.";
    }
    "TP/FP: human and automatic decisions."
}

fn lesson_note(app: &ShellApp) -> &'static str {
    let format = app.router.report().format();
    if app.router.report().provenance_details() {
        return lesson_export_note(format);
    }
    if kuzushi_core::workspace::workspace_export_omitted_fields(format).contains(&"lessons") {
        return "Lessons: omitted. JSON, JSONL, SARIF and Markdown preserve them.";
    }
    "Lessons: linked records preserved. p details."
}

fn report_scope_lines(app: &ShellApp) -> Vec<String> {
    if app.router.report().workspace_history() {
        return history_lines(app);
    }
    match report_document_view(app) {
        ReportReadView::Ready(receipt) | ReportReadView::Refreshing(receipt) => {
            selected_document_lines(app, &receipt)
        }
        ReportReadView::Empty => empty_receipt_lines(app),
        ReportReadView::Failed(error) => vec![
            "Scope: study receipt unavailable".into(),
            error,
            "s selects workspace history without a study coverage claim.".into(),
        ],
        _ => vec!["Scope: loading Scan study receipt…".into()],
    }
}

fn lesson_export_note(format: kuzushi_core::WorkspaceExportFormat) -> &'static str {
    if kuzushi_core::workspace::workspace_export_omitted_fields(format).contains(&"lessons") {
        return "Lessons: omitted by this format. JSON, JSONL, SARIF and Markdown bundle preserve linked lesson records.";
    }
    "Lessons: exports preserve current records linked to included finding generations, with acceptance, origin and reuse limits. Historical guidance does not establish a fix at another source revision."
}

fn empty_receipt_lines(app: &ShellApp) -> Vec<String> {
    if app.router.report().study().is_some() {
        return vec![
            "Scope: selected study receipt unavailable".into(),
            "Esc returns to its cases. s explicitly selects workspace history.".into(),
        ];
    }
    history_lines(app)
}

fn selected_document_lines(app: &ShellApp, document: &InvestigationReportDocument) -> Vec<String> {
    let explicit = app.router.report().study().is_some();
    let current = explicit
        || app
            .report_scan_attempt()
            .is_none_or(|attempt| attempt.current);
    let details = app.router.report().provenance_details();
    let mut lines = document_scope_lines(document, details, current);
    lines.splice(
        0..0,
        reassessment_lines(document.summary().reassessment_required_count),
    );
    let context_position = 1.min(lines.len());
    lines.splice(
        context_position..context_position,
        context_evidence::lines(document, details),
    );
    lines.extend(operator_brief_lines(document));
    lines.extend(context_guidance::lines(document));
    append_recorded_source_notice(&mut lines, explicit);
    append_document_engine_details(&mut lines, document, details);
    lines
}

fn document_scope_lines(
    document: &InvestigationReportDocument,
    details: bool,
    current: bool,
) -> Vec<String> {
    match document {
        InvestigationReportDocument::Study(receipt) => study_lines(receipt, details, current),
        InvestigationReportDocument::ContextMatrix(receipt) => {
            matrix::lines(receipt, details, current)
        }
        InvestigationReportDocument::ScopeStudy(receipt) => {
            scopes::lines(receipt, details, current)
        }
    }
}

fn append_recorded_source_notice(lines: &mut Vec<String>, explicit: bool) {
    if explicit {
        lines.insert(1, "This report describes recorded source. Current-source applicability has not been checked here.".into());
    }
}

fn operator_brief_lines(document: &InvestigationReportDocument) -> Vec<String> {
    let Some(brief) = document.summary().investigation_brief else {
        return Vec::new();
    };
    vec![
        format!(
            "Operator brief: {} · revision {}",
            brief.reference.brief_id, brief.reference.revision
        ),
        brief.document.text.clone(),
        "Operator intent guides priorities; finding decisions remain based on evidence.".into(),
    ]
}

fn history_lines(app: &ShellApp) -> Vec<String> {
    let mut lines = vec![
        "Scope: workspace history · all recorded source revisions".into(),
        "Finding review completeness does not describe repository coverage.".into(),
        "Workspace spend: total unavailable".into(),
    ];
    match report_workspace_review_view(app) {
        ReportReadView::Ready(summary) | ReportReadView::Refreshing(summary) => {
            lines.splice(0..0, reassessment_lines(summary.reassessment_required));
        }
        ReportReadView::Failed(error) => {
            lines.insert(1, format!("Review counts unavailable: {error}"));
        }
        _ => {}
    }
    lines.extend(scan_receipt::lines(app));
    lines
}

fn reassessment_lines(count: usize) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    let subject = if count == 1 {
        "finding needs"
    } else {
        "findings need"
    };
    vec![format!(
        "Review: {count} {subject} source reassessment. Earlier decisions remain recorded."
    )]
}

fn study_lines(receipt: &InvestigationReportReceipt, details: bool, current: bool) -> Vec<String> {
    let work = &receipt.occurrence;
    let mut lines = vec![format!("Scope: study {} · s switches to workspace history", receipt.campaign_id),
        format!("Work: {} completed / {} planned · {} failed · {} pending", work.completed, work.planned, work.failed, work.pending),
        format!("Evidence: {} producer observations · recurrence is separate from confidence", receipt.observation_count),
        "Coverage: engine and inventory omissions are not fully recorded; no complete coverage claim.".into(),
        source_label(receipt), context_label(receipt),
        discovery_model_line(receipt.equivalence.components.model.as_deref(), receipt.workers)];
    lines.splice(1..1, source_currency_lines(current));
    lines.splice(1..1, allowance_lines(receipt));
    lines.extend(scope::lines(&receipt.scope, details));
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
    source_components_label(&receipt.equivalence.components)
}

fn source_components_label(
    components: &kuzushi_core::capabilities::campaign::BatchEquivalenceComponents,
) -> String {
    match &components.target_git {
        Some(git) => format!(
            "Source: {} · {} · recorded content in p details",
            git.sha,
            if git.dirty { "dirty" } else { "clean" }
        ),
        None => "Source: unversioned · recorded content fingerprint in p details".into(),
    }
}

fn context_label(receipt: &InvestigationReportReceipt) -> String {
    context_components_label(&receipt.equivalence.components)
}

fn context_components_label(
    components: &kuzushi_core::capabilities::campaign::BatchEquivalenceComponents,
) -> String {
    match &components.threat_model {
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
    shared_allowance_lines(receipt.allowance.as_ref())
}

fn shared_allowance_lines(
    allowance: Option<&kuzushi_core::allowance::CampaignAllowanceReport>,
) -> Vec<String> {
    let Some(accounting) = allowance else {
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
    lines.extend(models::recorded_model_line(components.model.as_deref()));
    lines.extend(receipt.limitations.iter().cloned());
    lines
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod receipt_detail_tests {
    use super::*;
    #[test]
    fn retried_work_is_counted_as_attempts_without_inventing_more_jobs() {
        let lines = scan_detail_lines(7, 7).join("\n");
        assert!(lines.contains("7 / 7 attempts recorded"), "{lines}");
        assert!(!lines.contains("jobs"), "{lines}");
    }

    #[test]
    fn absent_engine_details_are_disclosed_without_claiming_attempts_or_coverage() {
        assert!(scan_detail_lines(0, 0).is_empty());
        let lines = scan_detail_lines(0, 1).join("\n");
        assert!(lines.contains("0 / 1 attempts recorded; 1 unavailable"));
        assert!(lines.contains("do not establish coverage"));
        assert_eq!(scan_detail_lines(1, 1).len(), 1);
    }

    #[test]
    fn completed_engine_keeps_partial_preparation_visible_in_report_details() {
        let mut engine = kuzushi_core::run_artifacts::ScanStageEngine {
            engine: "agentic".into(),
            outcome: kuzushi_core::run_artifacts::ScanEngineStageOutcome::Complete,
            rule_ids: None,
            run_ref: None,
            detail: Some(
                "Source preparation: 1 snippet. Partial preparation: file limit reached.".into(),
            ),
        };
        assert!(engine_detail_line(&engine)
            .unwrap()
            .contains("Partial preparation"));
        engine.detail = None;
        assert!(engine_detail_line(&engine).is_none());
    }

    #[test]
    fn repeated_engine_notes_keep_their_count_without_repeating_the_warning() {
        let lines = summarize_engine_details([
            "Engine agentic: Preparation is partial".into(),
            "Engine agentic: Preparation is partial".into(),
            "Engine semgrep: Missing coverage receipt".into(),
        ]);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Preparation is partial"));
        assert!(lines[0].contains("Recorded in 2 attempts"));
        assert!(lines[1].contains("Missing coverage receipt"));
    }
}
