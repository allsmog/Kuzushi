use super::review_queue::ReviewQueueMode;
use super::review_state::EffectiveReviewStateIndex;
use super::scoped_target_path_label;
use crate::{ShellApp, ViewDataState};
use kuzushi_core::workspace::{
    workspace_export_omitted_fields, workspace_finding_export_records_with_context,
    WorkspaceFindingExportRecord, WorkspaceFindingReviewContext, WorkspaceRunExportContext,
};
use kuzushi_core::{Finding, WorkspaceExportFormat};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportPreviewModel {
    pub(crate) format: String,
    pub(crate) completeness: &'static str,
    pub(crate) target: String,
    pub(crate) latest_run_id: Option<String>,
    pub(crate) generated_at: String,
    pub(crate) preview_metadata: &'static str,
    pub(crate) counts: ReportPreviewCounts,
    pub(crate) omitted_fields: Vec<&'static str>,
    pub(crate) rows: Vec<ReportPreviewRow>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReportPreviewCounts {
    pub(crate) total_findings: usize,
    pub(crate) included_findings: usize,
    pub(crate) open_decisions: usize,
    pub(crate) terminal_decisions: usize,
    pub(crate) included_open_decisions: usize,
    pub(crate) included_terminal_decisions: usize,
    pub(crate) critical: usize,
    pub(crate) high: usize,
    pub(crate) medium: usize,
    pub(crate) low: usize,
    pub(crate) info: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportPreviewRow {
    pub(crate) alias: String,
    pub(crate) identity_label: String,
    pub(crate) severity: String,
    pub(crate) confidence: String,
    pub(crate) decision: String,
    pub(crate) decision_conflict: Option<String>,
    pub(crate) lifecycle_status: String,
    pub(crate) evidence_state: String,
    pub(crate) provenance: String,
    pub(crate) tool: String,
    pub(crate) title: String,
    pub(crate) location: String,
}

pub(crate) fn report_preview_model(
    app: &ShellApp,
    format: WorkspaceExportFormat,
    mode: ReviewQueueMode,
) -> ReportPreviewModel {
    let preview = export_preview_records(app, mode);
    let rows = preview
        .records
        .iter()
        .map(ReportPreviewRow::from_export_record)
        .collect::<Vec<_>>();
    ReportPreviewModel {
        format: export_format_label(format).to_string(),
        completeness: mode.label(),
        target: scoped_target_path_label(app),
        latest_run_id: latest_run_id(app),
        generated_at: preview_generated_at(),
        preview_metadata: "preview-only; export projection; writes no review state",
        counts: report_preview_counts(
            &preview.records,
            preview.total_findings,
            preview.open_decisions,
            preview.included_open_decisions,
        ),
        omitted_fields: workspace_export_omitted_fields(format),
        rows,
    }
}

#[derive(Debug, Clone)]
struct ExportPreviewRecords {
    total_findings: usize,
    open_decisions: usize,
    included_open_decisions: usize,
    records: Vec<WorkspaceFindingExportRecord>,
}

fn export_preview_records(app: &ShellApp, mode: ReviewQueueMode) -> ExportPreviewRecords {
    let candidates = export_preview_candidates(app);
    let total_findings = candidates.len();
    let open_decisions = candidates
        .iter()
        .filter(|(finding, review)| !review_complete_for_finding(finding, review.as_ref()))
        .count();
    let included = candidates
        .into_iter()
        .filter(|(finding, review)| review_matches_mode(finding, review.as_ref(), mode))
        .collect::<Vec<_>>();
    let included_open_decisions = included
        .iter()
        .filter(|(finding, review)| !review_complete_for_finding(finding, review.as_ref()))
        .count();
    let (findings, reviews): (Vec<_>, Vec<_>) = included.into_iter().unzip();
    let run_contexts = export_preview_run_contexts(app, &findings);
    let records = workspace_finding_export_records_with_context(&findings, &reviews, &run_contexts);
    ExportPreviewRecords {
        total_findings,
        open_decisions,
        included_open_decisions,
        records,
    }
}

fn export_preview_candidates(
    app: &ShellApp,
) -> Vec<(Finding, Option<WorkspaceFindingReviewContext>)> {
    let review_index = EffectiveReviewStateIndex::from_findings_and_decisions(
        app.findings(),
        app.review_decisions(),
    );
    app.findings()
        .iter()
        .cloned()
        .map(|finding| {
            let review = review_index
                .effective_decision_for(&finding)
                .map(|decision| decision.export_review_context());
            (finding, review)
        })
        .collect()
}

fn export_preview_run_contexts(
    app: &ShellApp,
    findings: &[Finding],
) -> HashMap<String, WorkspaceRunExportContext> {
    let Some(target) = app.target() else {
        return HashMap::new();
    };
    let ViewDataState::Ready(index) = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_index(Some(target))
    else {
        return HashMap::new();
    };
    finding_run_ids(findings)
        .into_iter()
        .filter_map(|run_id| {
            let context = index
                .get(&run_id)
                .map(WorkspaceRunExportContext::from_summary)?;
            Some((run_id, context))
        })
        .collect()
}

fn finding_run_ids(findings: &[Finding]) -> Vec<String> {
    let mut run_ids = findings
        .iter()
        .filter_map(|finding| finding.scan_id.clone())
        .collect::<Vec<_>>();
    run_ids.sort();
    run_ids.dedup();
    run_ids
}

fn review_matches_mode(
    finding: &Finding,
    review: Option<&WorkspaceFindingReviewContext>,
    mode: ReviewQueueMode,
) -> bool {
    match mode {
        ReviewQueueMode::Open => !review_complete_for_finding(finding, review),
        ReviewQueueMode::Complete => review_complete_for_finding(finding, review),
        ReviewQueueMode::All => true,
    }
}

fn review_complete_for_finding(
    finding: &Finding,
    review: Option<&WorkspaceFindingReviewContext>,
) -> bool {
    review.is_some_and(|review| review.is_terminal_for_finding(finding))
}

fn report_preview_counts(
    records: &[WorkspaceFindingExportRecord],
    total_findings: usize,
    open_decisions: usize,
    included_open_decisions: usize,
) -> ReportPreviewCounts {
    let mut counts = ReportPreviewCounts {
        total_findings,
        included_findings: records.len(),
        open_decisions,
        terminal_decisions: total_findings.saturating_sub(open_decisions),
        included_open_decisions,
        included_terminal_decisions: records.len().saturating_sub(included_open_decisions),
        ..ReportPreviewCounts::default()
    };
    for record in records {
        match record.severity.as_str() {
            "critical" => counts.critical += 1,
            "high" => counts.high += 1,
            "medium" => counts.medium += 1,
            "low" => counts.low += 1,
            "info" => counts.info += 1,
            _ => {}
        }
    }
    counts
}

fn latest_run_id(app: &ShellApp) -> Option<String> {
    let target = app.target()?;
    match app
        .workbench_cache()
        .borrow()
        .cached_latest_run_pointer(Some(target))
    {
        ViewDataState::Ready(kuzushi_core::LatestRunPointerState::Ready(run_id)) => {
            Some(run_id.as_str().to_string())
        }
        ViewDataState::Ready(kuzushi_core::LatestRunPointerState::Missing)
        | ViewDataState::Ready(kuzushi_core::LatestRunPointerState::Invalid(_))
        | ViewDataState::NotRequested
        | ViewDataState::Loading => None,
    }
}

fn preview_generated_at() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{secs}")
}

fn export_format_label(format: WorkspaceExportFormat) -> &'static str {
    match format {
        WorkspaceExportFormat::Json => "json",
        WorkspaceExportFormat::Jsonl => "jsonl",
        WorkspaceExportFormat::Sarif => "sarif",
        WorkspaceExportFormat::Csv => "csv",
        WorkspaceExportFormat::MarkdownBundle => "markdown-bundle",
        WorkspaceExportFormat::VulnFindings => "vuln-findings",
    }
}

impl ReportPreviewRow {
    fn from_export_record(record: &WorkspaceFindingExportRecord) -> Self {
        Self {
            alias: record.alias.clone(),
            identity_label: export_identity_label(record.identity_id.as_deref()),
            severity: record.severity.to_ascii_uppercase(),
            confidence: export_confidence_label(record.confidence),
            decision: record.review_decision.clone(),
            decision_conflict: record.review_decision_conflict.clone(),
            lifecycle_status: record.lifecycle_status.clone(),
            evidence_state: record.evidence.state.clone(),
            provenance: export_provenance_label(record),
            tool: record.tool.clone(),
            title: record.title.clone(),
            location: super::source_location::source_location_label(
                &record.location.file,
                Some(u64::from(record.location.start_line)),
                None,
                None,
            ),
        }
    }
}

fn export_identity_label(identity_id: Option<&str>) -> String {
    identity_id
        .map(str::trim)
        .filter(|identity_id| identity_id.len() >= 11 && identity_id.starts_with("fi_"))
        .map(|identity_id| format!("FI-{}", &identity_id[3..11]))
        .unwrap_or_else(|| "-".to_string())
}

fn export_confidence_label(confidence: Option<f32>) -> String {
    confidence
        .map(|confidence| format!("{:.0}%", confidence.clamp(0.0, 1.0) * 100.0))
        .unwrap_or_else(|| "-".to_string())
}

fn export_provenance_label(record: &WorkspaceFindingExportRecord) -> String {
    let mut parts = [
        record
            .run_id
            .as_deref()
            .map(|run_id| format!("run:{run_id}")),
        record
            .provenance
            .run_status
            .as_deref()
            .map(|status| format!("status:{status}")),
        record
            .provenance
            .model
            .as_deref()
            .map(|model| format!("model:{model}")),
        record
            .provenance
            .runtime_platform
            .as_deref()
            .map(|runtime| format!("runtime:{runtime}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !record.provenance.source_history.is_empty() {
        parts.push(format!(
            "sources:{} history entries:{}",
            record.evidence.source_count,
            record.provenance.source_history.len()
        ));
    }
    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join(" ")
    }
}

#[cfg(test)]
#[path = "tests/report_preview.rs"]
mod tests;
