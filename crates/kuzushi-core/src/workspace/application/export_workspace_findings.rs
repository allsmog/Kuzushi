use super::export_markdown_bundle::write_markdown_bundle;
use super::export_metadata::{workspace_export_metadata_value, workspace_export_omitted_fields};
use super::export_projection::workspace_finding_export_records_with_context;
use super::export_projection_model::{WorkspaceFindingExportRecord, WorkspaceRunExportContext};
use super::export_review_context::WorkspaceFindingReviewContext;
use super::export_sarif::findings_to_sarif;
use super::*;
use crate::findings::ReviewDecisionRecord;
use crate::run_artifacts::load_run_summary;
use std::collections::HashMap;

pub fn export_workspace_findings(
    workspace: &WorkspaceTarget,
    output_path: impl AsRef<Path>,
    format: Option<WorkspaceExportFormat>,
) -> Result<WorkspaceFindingsExport> {
    export_workspace_findings_with_options(
        workspace,
        output_path,
        WorkspaceExportOptions::new(format),
    )
}

pub fn export_workspace_findings_with_options(
    workspace: &WorkspaceTarget,
    output_path: impl AsRef<Path>,
    options: WorkspaceExportOptions,
) -> Result<WorkspaceFindingsExport> {
    let output_path = output_path.as_ref();
    if output_path.as_os_str().is_empty() {
        anyhow::bail!("workspace findings export needs an output path");
    }
    let format = resolve_workspace_findings_export_format(output_path, options.format)?;
    validate_workspace_findings_output_path(output_path, format)?;

    let prepared = prepare_workspace_findings_export(workspace, options)?;
    ensure_empty_export_is_allowed(&prepared.records, options)?;
    ensure_workspace_export_parent(output_path)?;
    write_workspace_findings_export(
        workspace,
        &prepared.findings,
        &prepared.records,
        format,
        output_path,
        options,
        prepared.total_count,
    )?;

    Ok(WorkspaceFindingsExport {
        output_path: output_path.to_path_buf(),
        format,
        count: prepared.records.len(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceFindingsExportPreview {
    pub format: WorkspaceExportFormat,
    pub completeness: WorkspaceExportCompleteness,
    pub count: usize,
    pub total_count: usize,
    pub omitted_fields: Vec<&'static str>,
    pub body: String,
}

pub fn preview_workspace_findings_export(
    workspace: &WorkspaceTarget,
    format: WorkspaceExportFormat,
    options: WorkspaceExportOptions,
) -> Result<WorkspaceFindingsExportPreview> {
    if format == WorkspaceExportFormat::MarkdownBundle {
        anyhow::bail!(
            "markdown-bundle preview is directory-shaped; use json, jsonl, sarif, or csv preview"
        );
    }
    let options = WorkspaceExportOptions {
        format: Some(format),
        completeness: options.completeness,
        allow_empty: options.allow_empty,
    };
    let prepared = prepare_workspace_findings_export(workspace, options)?;
    ensure_empty_export_is_allowed(&prepared.records, options)?;
    let body = render_workspace_findings_export(
        workspace,
        &prepared.records,
        format,
        options,
        prepared.total_count,
    )?;
    Ok(WorkspaceFindingsExportPreview {
        format,
        completeness: options.completeness,
        count: prepared.records.len(),
        total_count: prepared.total_count,
        omitted_fields: workspace_export_omitted_fields(format),
        body,
    })
}

struct PreparedWorkspaceFindingsExport {
    findings: Vec<Finding>,
    records: Vec<WorkspaceFindingExportRecord>,
    total_count: usize,
}

fn prepare_workspace_findings_export(
    workspace: &WorkspaceTarget,
    options: WorkspaceExportOptions,
) -> Result<PreparedWorkspaceFindingsExport> {
    let store = FindingStore::open(workspace.findings_db_path())?;
    let all_findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    let all_reviews = effective_review_contexts(&store, &all_findings)?;
    let total_count = all_findings.len();
    let (findings, reviews) =
        filter_export_findings(all_findings, all_reviews, options.completeness);
    let run_contexts = workspace_run_export_contexts(workspace, &findings);
    let records = workspace_finding_export_records_with_context(&findings, &reviews, &run_contexts);
    Ok(PreparedWorkspaceFindingsExport {
        findings,
        records,
        total_count,
    })
}

fn workspace_run_export_contexts(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
) -> HashMap<String, WorkspaceRunExportContext> {
    finding_run_ids(findings)
        .into_iter()
        .filter_map(|run_id| {
            let context = load_run_summary(workspace.root(), &run_id)
                .ok()
                .map(|summary| WorkspaceRunExportContext::from_summary(&summary))?;
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

fn validate_workspace_findings_output_path(
    output_path: &Path,
    format: WorkspaceExportFormat,
) -> Result<()> {
    match format {
        WorkspaceExportFormat::MarkdownBundle => validate_markdown_bundle_path(output_path),
        _ => validate_single_file_path(output_path),
    }
}

fn ensure_empty_export_is_allowed(
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
) -> Result<()> {
    if !records.is_empty() || options.allow_empty {
        return Ok(());
    }
    anyhow::bail!(
        "workspace findings export selected 0 findings; empty exports are valid but require explicit allow_empty=true or --allow-empty"
    )
}

fn validate_single_file_path(output_path: &Path) -> Result<()> {
    if output_path.exists() && output_path.is_dir() {
        anyhow::bail!(
            "workspace findings export output must be a file path, not directory: {}",
            output_path.display()
        );
    }
    Ok(())
}

fn validate_markdown_bundle_path(output_path: &Path) -> Result<()> {
    if !output_path.exists() {
        return Ok(());
    }
    if !output_path.is_dir() {
        anyhow::bail!(
            "markdown-bundle export needs a directory path, not a file: {}",
            output_path.display()
        );
    }
    let mut entries = fs::read_dir(output_path)
        .with_context(|| format!("Could not read {}", output_path.display()))?;
    if entries.next().is_some() {
        anyhow::bail!(
            "markdown-bundle output directory must be empty: {}",
            output_path.display()
        );
    }
    Ok(())
}

fn resolve_workspace_findings_export_format(
    output_path: &Path,
    format: Option<WorkspaceExportFormat>,
) -> Result<WorkspaceExportFormat> {
    match format {
        Some(format) => Ok(format),
        None => WorkspaceExportFormat::from_output_path(output_path),
    }
}

fn ensure_workspace_export_parent(output_path: &Path) -> Result<()> {
    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    Ok(())
}

fn write_workspace_findings_export(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    records: &[WorkspaceFindingExportRecord],
    format: WorkspaceExportFormat,
    output_path: &Path,
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<()> {
    if format == WorkspaceExportFormat::MarkdownBundle {
        return write_markdown_bundle(
            workspace,
            findings,
            records,
            output_path,
            options,
            total_count,
        );
    }
    let body = render_workspace_findings_export(workspace, records, format, options, total_count)?;
    fs::write(output_path, body)
        .with_context(|| format!("Could not write {}", output_path.display()))
}

fn render_workspace_findings_export(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    format: WorkspaceExportFormat,
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<String> {
    match format {
        WorkspaceExportFormat::Json => {
            workspace_findings_to_json(workspace, records, options, total_count)
        }
        WorkspaceExportFormat::Jsonl => findings_to_jsonl(records, options, total_count),
        WorkspaceExportFormat::Sarif => findings_to_sarif(workspace, records, options, total_count),
        WorkspaceExportFormat::Csv => findings_to_csv(records, options, total_count),
        WorkspaceExportFormat::MarkdownBundle => {
            anyhow::bail!("markdown-bundle is a directory output; routed via write_markdown_bundle")
        }
    }
}

fn workspace_findings_to_json(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<String> {
    Ok(serde_json::to_string_pretty(&json!({
        "format": "kuzushi.workspace.findings.v2",
        "workspaceRoot": workspace.root().display().to_string(),
        "findingsDb": workspace.findings_db_path().display().to_string(),
        "completeness": options.completeness.as_str(),
        "count": records.len(),
        "includedCount": records.len(),
        "totalCount": total_count,
        "metadata": workspace_export_metadata_value(
            WorkspaceExportFormat::Json,
            options,
            records.len(),
            total_count,
        ),
        "findings": records,
    }))?)
}

fn filter_export_findings(
    findings: Vec<Finding>,
    reviews: Vec<Option<WorkspaceFindingReviewContext>>,
    completeness: WorkspaceExportCompleteness,
) -> (Vec<Finding>, Vec<Option<WorkspaceFindingReviewContext>>) {
    findings
        .into_iter()
        .zip(reviews)
        .filter(|(finding, review)| {
            finding_matches_export_completeness(finding, review.as_ref(), completeness)
        })
        .unzip()
}

fn effective_review_contexts(
    store: &FindingStore,
    findings: &[Finding],
) -> Result<Vec<Option<WorkspaceFindingReviewContext>>> {
    let mut identity_reviews = HashMap::new();
    findings
        .iter()
        .map(|finding| effective_review_context(store, finding, &mut identity_reviews))
        .collect()
}

fn finding_matches_export_completeness(
    finding: &Finding,
    review: Option<&WorkspaceFindingReviewContext>,
    completeness: WorkspaceExportCompleteness,
) -> bool {
    match completeness {
        WorkspaceExportCompleteness::All => true,
        WorkspaceExportCompleteness::Open => !has_terminal_review_decision(finding, review),
        WorkspaceExportCompleteness::Complete => has_terminal_review_decision(finding, review),
    }
}

fn effective_review_context(
    store: &FindingStore,
    finding: &Finding,
    identity_reviews: &mut HashMap<String, Option<ReviewDecisionRecord>>,
) -> Result<Option<WorkspaceFindingReviewContext>> {
    let latest = latest_stored_review_context(store, finding, identity_reviews)?;
    Ok(latest.or_else(|| WorkspaceFindingReviewContext::from_finding(finding)))
}

fn latest_stored_review_context(
    store: &FindingStore,
    finding: &Finding,
    identity_reviews: &mut HashMap<String, Option<ReviewDecisionRecord>>,
) -> Result<Option<WorkspaceFindingReviewContext>> {
    if let Some(identity_id) = finding.identity_id.as_ref() {
        if let Some(record) = identity_reviews.get(identity_id) {
            return Ok(record.as_ref().map(|record| {
                WorkspaceFindingReviewContext::from_record_for_finding(record, finding)
            }));
        }
        let record = store.latest_review_decision_for_identity(identity_id)?;
        let review = record
            .as_ref()
            .map(|record| WorkspaceFindingReviewContext::from_record_for_finding(record, finding));
        identity_reviews.insert(identity_id.clone(), record);
        return Ok(review);
    }
    match finding.id {
        Some(finding_id) => Ok(store
            .latest_review_decision(finding_id)?
            .as_ref()
            .map(WorkspaceFindingReviewContext::from_record)),
        None => Ok(None),
    }
}

fn has_terminal_review_decision(
    finding: &Finding,
    review: Option<&WorkspaceFindingReviewContext>,
) -> bool {
    review
        .map(|review| review.is_terminal_for_finding(finding))
        .or_else(|| {
            WorkspaceFindingReviewContext::from_finding(finding)
                .map(|review| review.is_terminal_for_finding(finding))
        })
        .unwrap_or(false)
}

pub(crate) fn findings_to_jsonl(
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<String> {
    let mut lines = String::new();
    lines.push_str(&serde_json::to_string(&json!({
        "recordType": "metadata",
        "metadata": workspace_export_metadata_value(
            WorkspaceExportFormat::Jsonl,
            options,
            records.len(),
            total_count,
        ),
    }))?);
    lines.push('\n');
    for record in records {
        lines.push_str(&serde_json::to_string(record)?);
        lines.push('\n');
    }
    Ok(lines)
}

pub(crate) fn findings_to_csv(
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::<u8>::new());
    write_csv_header(&mut writer)?;
    write_csv_rows(&mut writer, records, options, total_count)?;
    finalize_csv_writer(writer)
}

const CSV_FINDINGS_HEADER: &[&str] = &[
    "alias",
    "identity_id",
    "fingerprint",
    "kind",
    "rule_id",
    "title",
    "severity",
    "file",
    "start_line",
    "end_line",
    "confidence",
    "priority",
    "lifecycle_status",
    "review_decision",
    "review_decision_conflict",
    "review_decision_author",
    "triage_verdict",
    "suppressed",
    "evidence_state",
    "observed_evidence_present",
    "observed_evidence_count",
    "observed_code_evidence_count",
    "observed_capture_evidence_count",
    "observed_other_evidence_count",
    "model_generated_reasoning_present",
    "model_generated_reasoning_count",
    "derived_source_present",
    "automated_reasoning_present",
    "static_proof_state",
    "proof_confidence",
    "verification",
    "tool",
    "vuln_source",
    "source_signature",
    "corroboration_count",
    "run_id",
    "run_status",
    "kuzushi_version",
    "model",
    "export_completeness",
    "export_included_count",
    "export_total_count",
    "format_omitted_fields",
];

fn write_csv_header(writer: &mut csv::Writer<Vec<u8>>) -> Result<()> {
    writer.write_record(CSV_FINDINGS_HEADER.iter().copied())?;
    Ok(())
}

fn write_csv_rows(
    writer: &mut csv::Writer<Vec<u8>>,
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<()> {
    let metadata = csv_metadata_fields(records.len(), total_count, options);
    for record in records {
        writer.write_record(csv_finding_row(record, &metadata))?;
    }
    Ok(())
}

fn finalize_csv_writer(writer: csv::Writer<Vec<u8>>) -> Result<String> {
    let bytes = writer
        .into_inner()
        .context("Could not finalize CSV export buffer")?;
    String::from_utf8(bytes).context("CSV export produced non-UTF-8 output")
}

fn csv_metadata_fields(
    included_count: usize,
    total_count: usize,
    options: WorkspaceExportOptions,
) -> [String; 4] {
    [
        options.completeness.as_str().to_string(),
        included_count.to_string(),
        total_count.to_string(),
        workspace_export_omitted_fields(WorkspaceExportFormat::Csv).join(";"),
    ]
}

fn csv_finding_row(record: &WorkspaceFindingExportRecord, metadata: &[String; 4]) -> Vec<String> {
    let mut row = csv_core_fields(record);
    row.extend(csv_review_fields(record));
    row.extend(csv_signal_fields(record));
    row.extend(csv_provenance_fields(record));
    row.extend(metadata.iter().cloned());
    row
}

fn csv_core_fields(record: &WorkspaceFindingExportRecord) -> Vec<String> {
    vec![
        record.alias.clone(),
        record.identity_id.clone().unwrap_or_default(),
        record.fingerprint.clone(),
        record.kind.clone(),
        record.rule_id.clone(),
        record.title.clone(),
        record.severity.clone(),
        record.location.file.clone(),
        record.location.start_line.to_string(),
        record
            .location
            .end_line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        record
            .confidence
            .map(|confidence| format!("{confidence:.2}"))
            .unwrap_or_default(),
        record.priority.clone(),
        record.lifecycle_status.clone(),
    ]
}

fn csv_review_fields(record: &WorkspaceFindingExportRecord) -> Vec<String> {
    vec![
        record.review_decision.clone(),
        record.review_decision_conflict.clone().unwrap_or_default(),
        record.review_decision_author.clone().unwrap_or_default(),
        record.triage_verdict.clone().unwrap_or_default(),
        record.suppressed.to_string(),
    ]
}

fn csv_signal_fields(record: &WorkspaceFindingExportRecord) -> Vec<String> {
    vec![
        record.evidence.state.clone(),
        record.evidence.observed_evidence_present.to_string(),
        record.evidence.observed_count.to_string(),
        record.evidence.observed_code_count.to_string(),
        record.evidence.observed_capture_count.to_string(),
        record.evidence.observed_other_count.to_string(),
        record.evidence.model_generated_reasoning_present.to_string(),
        record.evidence.model_generated_reasoning_count.to_string(),
        record.evidence.derived_source_present.to_string(),
        record.analysis.automated_reasoning_present.to_string(),
        record.static_proof_state.clone(),
        record.proof_confidence.clone(),
        record.verification.label.clone(),
    ]
}

fn csv_provenance_fields(record: &WorkspaceFindingExportRecord) -> Vec<String> {
    vec![
        record.tool.clone(),
        record.vuln_source.clone(),
        record.source_signature.clone().unwrap_or_default(),
        record.corroboration_count.to_string(),
        record.run_id.clone().unwrap_or_default(),
        record.provenance.run_status.clone().unwrap_or_default(),
        record.provenance.kuzushi_version.clone().unwrap_or_default(),
        record.provenance.model.clone().unwrap_or_default(),
    ]
}
