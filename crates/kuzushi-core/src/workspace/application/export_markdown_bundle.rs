//! M1 §1.4 — markdown bundle export. Output is a directory containing
//! `README.md` (projection summary), per-finding `.md` files, and
//! `manifest.json`. Lives in its own module to keep
//! `export_workspace_findings.rs` under the 300-line per-file limit
//! enforced by the CRAP-risk gate.

use super::export_evidence_origin::finding_evidence_origin_label;
use super::export_metadata::workspace_export_metadata_value;
use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;
use crate::findings::FindingEvidence;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundleFileEntry {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BundleFindingFile {
    alias: String,
    file: BundleFileEntry,
}

pub(crate) fn write_markdown_bundle(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    records: &[WorkspaceFindingExportRecord],
    output_dir: &Path,
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;
    let findings_dir = output_dir.join("findings");
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("Could not create {}", findings_dir.display()))?;

    let readme_file = write_bundle_readme(workspace, records, output_dir, options, total_count)?;
    let finding_files = write_bundle_finding_files(findings, records, &findings_dir)?;
    write_bundle_manifest(
        workspace,
        records,
        output_dir,
        options,
        total_count,
        &readme_file,
        &finding_files,
    )
}

fn write_bundle_readme(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    output_dir: &Path,
    options: WorkspaceExportOptions,
    total_count: usize,
) -> Result<BundleFileEntry> {
    let readme = render_bundle_readme_markdown(workspace, records, options, total_count);
    let path = output_dir.join("README.md");
    write_bundle_text_file(&path, "README.md", &readme)
}

fn render_bundle_readme_markdown(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) -> String {
    let mut out = String::new();
    push_readme_header(&mut out, workspace, records, options, total_count);
    push_readme_summary(&mut out, records);
    push_readme_findings_table(&mut out, records);
    out
}

fn push_readme_header(
    out: &mut String,
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: WorkspaceExportOptions,
    total_count: usize,
) {
    out.push_str("# Kuzushi findings bundle\n\n");
    out.push_str(&format!("- **Target:** `{}`\n", workspace.root().display()));
    out.push_str("- **Projection:** `WorkspaceFindingExportRecord`\n");
    out.push_str(&format!(
        "- **Completeness:** `{}`\n",
        options.completeness.as_str()
    ));
    out.push_str(&format!(
        "- **Included:** {} of {} finding(s)\n",
        records.len(),
        total_count
    ));
    out.push_str(&format!(
        "- **Omitted fields:** {}\n\n",
        omitted_fields_label()
    ));
}

fn omitted_fields_label() -> String {
    let fields = super::export_metadata::workspace_export_omitted_fields(
        WorkspaceExportFormat::MarkdownBundle,
    );
    if fields.is_empty() {
        "none".to_string()
    } else {
        fields.join(", ")
    }
}

fn push_readme_summary(out: &mut String, records: &[WorkspaceFindingExportRecord]) {
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- **Severity:** {}\n",
        projection_count_summary(records, |record| record.severity.as_str())
    ));
    out.push_str(&format!(
        "- **Review decisions:** {}\n",
        projection_count_summary(records, |record| record.review_decision.as_str())
    ));
    out.push_str(&format!(
        "- **Evidence states:** {}\n\n",
        projection_count_summary(records, |record| record.evidence.state.as_str())
    ));
}

fn projection_count_summary(
    records: &[WorkspaceFindingExportRecord],
    key: impl Fn(&WorkspaceFindingExportRecord) -> &str,
) -> String {
    let mut counts = BTreeMap::<String, usize>::new();
    for record in records {
        *counts.entry(key(record).to_string()).or_default() += 1;
    }
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .into_iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn push_readme_findings_table(out: &mut String, records: &[WorkspaceFindingExportRecord]) {
    out.push_str("## Findings\n\n");
    out.push_str(
        "| Alias | Severity | Confidence | Decision | Lifecycle | Evidence | Location |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for record in records {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | `{}:{}` |\n",
            markdown_table_cell(&record.alias),
            markdown_table_cell(&record.severity),
            markdown_table_cell(&record.proof_confidence),
            markdown_table_cell(&record.review_decision),
            markdown_table_cell(&record.lifecycle_status),
            markdown_table_cell(&record.evidence.state),
            record.location.file,
            record.location.start_line
        ));
    }
    if records.is_empty() {
        out.push_str("| - | - | - | - | - | - | - |\n");
    }
    out.push('\n');
}

fn markdown_table_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn write_bundle_finding_files(
    findings: &[Finding],
    records: &[WorkspaceFindingExportRecord],
    findings_dir: &Path,
) -> Result<Vec<BundleFindingFile>> {
    let findings_by_fingerprint = findings_by_fingerprint(findings);
    let mut files = Vec::new();
    for record in records {
        let alias = &record.alias;
        let finding = findings_by_fingerprint
            .get(record.fingerprint.as_str())
            .with_context(|| format!("missing finding source for {alias}"))?;
        let body = render_bundle_finding_markdown(record, finding);
        let relative_path = format!("findings/{alias}.md");
        let file = write_bundle_text_file(
            &findings_dir.join(format!("{alias}.md")),
            &relative_path,
            &body,
        )?;
        files.push(BundleFindingFile {
            alias: alias.clone(),
            file,
        });
    }
    Ok(files)
}

fn findings_by_fingerprint(findings: &[Finding]) -> HashMap<&str, &Finding> {
    findings
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect()
}

fn render_bundle_finding_markdown(
    record: &WorkspaceFindingExportRecord,
    finding: &Finding,
) -> String {
    let mut out = String::new();
    push_bundle_header(&mut out, record);
    push_bundle_message(&mut out, finding);
    if !finding.evidence.is_empty() {
        out.push_str("## Evidence\n\n");
        for piece in &finding.evidence {
            push_bundle_evidence(&mut out, piece);
        }
    }
    out
}

fn push_bundle_header(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!("# {} · {}\n\n", record.alias, record.title));
    out.push_str(&format!("- **Severity:** {}\n", record.severity));
    out.push_str(&format!(
        "- **Review decision:** {}\n",
        record.review_decision
    ));
    if let Some(conflict) = record.review_decision_conflict.as_deref() {
        out.push_str(&format!("- **Decision conflict:** {conflict}\n"));
    }
    out.push_str(&format!(
        "- **Lifecycle status:** {}\n",
        record.lifecycle_status
    ));
    push_bundle_evidence_summary(out, record);
    push_bundle_analysis_summary(out, record);
    out.push_str(&format!("- **Tool:** {}\n", record.tool));
    out.push_str(&format!("- **Rule:** `{}`\n", record.rule_id));
    out.push_str(&format!("- **Fingerprint:** `{}`\n", record.fingerprint));
    push_bundle_run_provenance(out, record);
    push_bundle_remediation(out, record);
    out.push_str(&format!(
        "- **Location:** `{}:{}`\n\n",
        record.location.file, record.location.start_line
    ));
}

fn push_bundle_remediation(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(remediation) = record.remediation.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Remediation:** {} (`{}`)\n",
        remediation.application_state, remediation.application_id
    ));
    out.push_str(&format!(
        "- **Patch run:** `{}` · diff `{}`\n",
        remediation.patch_run_id, remediation.diff_hash
    ));
    if let Some(outcome) = remediation.reverify_outcome.as_deref() {
        out.push_str(&format!("- **Re-verification:** {outcome}"));
        if let Some(run_id) = remediation.reverify_run_id.as_deref() {
            out.push_str(&format!(" (`{run_id}`)"));
        }
        out.push('\n');
    }
    if !remediation.touched_paths.is_empty() {
        out.push_str(&format!(
            "- **Touched paths:** {}\n",
            remediation.touched_paths.join(", ")
        ));
    }
}

fn push_bundle_evidence_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "- **Evidence state:** {} ({} observed)\n",
        record.evidence.state, record.evidence.observed_count
    ));
    out.push_str(&format!(
        "- **Evidence origin:** observed={} code={} capture={} other={} model-generated-reasoning={} derived-source={}\n",
        record.evidence.observed_evidence_present,
        record.evidence.observed_code_count,
        record.evidence.observed_capture_count,
        record.evidence.observed_other_count,
        record.evidence.model_generated_reasoning_count,
        record.evidence.derived_source_present
    ));
}

fn push_bundle_analysis_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "- **Automated reasoning:** {}\n",
        record.analysis.automated_reasoning_present
    ));
    out.push_str(&format!("- **Confidence:** {}\n", record.proof_confidence));
    out.push_str(&format!(
        "- **Static proof:** {} ({})\n",
        record.static_proof_label, record.static_proof_state
    ));
    out.push_str(&format!(
        "- **Verification:** {}\n",
        record.verification.label
    ));
}

fn push_bundle_run_provenance(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(run_id) = record.provenance.run_id.as_deref() else {
        return;
    };
    out.push_str(&format!("- **Run:** `{run_id}`"));
    if let Some(status) = record.provenance.run_status.as_deref() {
        out.push_str(&format!(" ({status})"));
    }
    if let Some(model) = record.provenance.model.as_deref() {
        out.push_str(&format!(" model `{model}`"));
    }
    out.push('\n');
}

fn push_bundle_message(out: &mut String, finding: &Finding) {
    out.push_str("## Message\n\n");
    out.push_str(&finding.message);
    out.push_str("\n\n");
}

fn push_bundle_evidence(out: &mut String, evidence: &FindingEvidence) {
    out.push_str(&format!(
        "### {kind} · {file}:{line}\n\n",
        kind = evidence.kind,
        file = evidence.file_path,
        line = evidence.line
    ));
    out.push_str(&format!(
        "_Origin: {}_\n\n",
        finding_evidence_origin_label(evidence)
    ));
    if !evidence.snippet.is_empty() {
        out.push_str("```\n");
        out.push_str(&evidence.snippet);
        out.push_str("\n```\n\n");
    }
    if !evidence.rationale.is_empty() {
        out.push_str(&evidence.rationale);
        out.push_str("\n\n");
    }
}

fn write_bundle_manifest(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    output_dir: &Path,
    options: WorkspaceExportOptions,
    total_count: usize,
    readme_file: &BundleFileEntry,
    finding_files: &[BundleFindingFile],
) -> Result<()> {
    let files_by_alias = finding_files_by_alias(finding_files);
    let entries = records
        .iter()
        .map(|record| build_manifest_entry(record, &files_by_alias))
        .collect::<Result<Vec<_>>>()?;
    let document = json!({
        "format": "kuzushi.workspace.findings-bundle.v1",
        "workspaceRoot": workspace.root().display().to_string(),
        "completeness": options.completeness.as_str(),
        "count": records.len(),
        "includedCount": records.len(),
        "totalCount": total_count,
        "metadata": workspace_export_metadata_value(
            WorkspaceExportFormat::MarkdownBundle,
            options,
            records.len(),
            total_count,
        ),
        "files": bundle_files_manifest(readme_file, finding_files),
        "findings": entries,
    });
    let path = output_dir.join("manifest.json");
    fs::write(&path, serde_json::to_string_pretty(&document)?)
        .with_context(|| format!("Could not write {}", path.display()))
}

fn finding_files_by_alias(finding_files: &[BundleFindingFile]) -> HashMap<&str, &BundleFileEntry> {
    finding_files
        .iter()
        .map(|file| (file.alias.as_str(), &file.file))
        .collect()
}

fn build_manifest_entry(
    record: &WorkspaceFindingExportRecord,
    files_by_alias: &HashMap<&str, &BundleFileEntry>,
) -> Result<serde_json::Value> {
    let file = files_by_alias
        .get(record.alias.as_str())
        .with_context(|| format!("missing markdown file for {}", record.alias))?;
    Ok(json!({
        "alias": record.alias,
        "fingerprint": record.fingerprint,
        "severity": record.severity,
        "proofConfidence": record.proof_confidence,
        "tool": record.tool,
        "ruleId": record.rule_id,
        "file": record.location.file,
        "startLine": record.location.start_line,
        "reviewDecision": record.review_decision,
        "reviewDecisionConflict": record.review_decision_conflict,
        "lifecycleStatus": record.lifecycle_status,
        "evidenceState": record.evidence.state,
        "observedEvidencePresent": record.evidence.observed_evidence_present,
        "observedCodeEvidenceCount": record.evidence.observed_code_count,
        "observedCaptureEvidenceCount": record.evidence.observed_capture_count,
        "observedOtherEvidenceCount": record.evidence.observed_other_count,
        "modelGeneratedReasoningPresent": record.evidence.model_generated_reasoning_present,
        "modelGeneratedReasoningCount": record.evidence.model_generated_reasoning_count,
        "derivedSourcePresent": record.evidence.derived_source_present,
        "automatedReasoningPresent": record.analysis.automated_reasoning_present,
        "runId": record.provenance.run_id,
        "runStatus": record.provenance.run_status,
        "model": record.provenance.model,
        "path": file.path,
        "sha256": file.sha256,
    }))
}

fn bundle_files_manifest(
    readme_file: &BundleFileEntry,
    finding_files: &[BundleFindingFile],
) -> Vec<serde_json::Value> {
    std::iter::once(readme_file)
        .chain(finding_files.iter().map(|finding| &finding.file))
        .map(bundle_file_manifest_entry)
        .collect()
}

fn bundle_file_manifest_entry(file: &BundleFileEntry) -> serde_json::Value {
    json!({
        "path": file.path,
        "sha256": file.sha256,
    })
}

fn write_bundle_text_file(path: &Path, relative_path: &str, body: &str) -> Result<BundleFileEntry> {
    fs::write(path, body).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(BundleFileEntry {
        path: relative_path.to_string(),
        sha256: bundle_text_sha256(body),
    })
}

fn bundle_text_sha256(body: &str) -> String {
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(body.as_bytes())
    )
}
