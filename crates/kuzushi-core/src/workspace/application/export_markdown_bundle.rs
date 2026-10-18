//! Markdown bundle file writing and manifest authentication.

use super::export_evidence_origin::finding_evidence_origin_label;
use super::export_metadata::workspace_export_metadata_value;
use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;
use crate::findings::FindingEvidence;
use std::collections::{BTreeMap, HashMap};

mod finding;
mod formatting;
mod publication;
mod readme;
mod review;
use finding::render_bundle_finding_markdown;
pub(super) use publication::{publish_bundle, validate_destination};
use readme::render_bundle_readme_markdown;

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
    options: &WorkspaceExportOptions,
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
    options: &WorkspaceExportOptions,
    total_count: usize,
) -> Result<BundleFileEntry> {
    let readme = render_bundle_readme_markdown(workspace, records, options, total_count);
    let path = output_dir.join("README.md");
    write_bundle_text_file(&path, "README.md", &readme)
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

fn write_bundle_manifest(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    output_dir: &Path,
    options: &WorkspaceExportOptions,
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
    let mut entry = json!({
        "alias": record.alias,
        "fingerprint": record.fingerprint,
        "severity": record.severity,
        "proofConfidence": record.proof_confidence,
        "tool": record.tool,
        "ruleId": record.rule_id,
        "file": record.location.file,
        "startLine": record.location.start_line,
        "reviewDecision": record.review_decision,
        "reviewDecisionBasis": record.review_decision_basis,
        "reviewedSource": record.reviewed_source,
        "goalAssessments": record.goal_assessments,
        "relationships": record.relationships,
        "observationGap": record.observation_gap,
        "observationNote": record.observation_note,
        "reviewDecisionConflict": record.review_decision_conflict,
        "lifecycleStatus": record.lifecycle_status,
        "automatedReasoningPresent": record.analysis.automated_reasoning_present,
        "runId": record.provenance.run_id,
        "sourceHistory": record.provenance.source_history,
        "runStatus": record.provenance.run_status,
        "model": record.provenance.model,
        "path": file.path,
        "sha256": file.sha256,
    });
    append_manifest_evidence(&mut entry, record);
    Ok(entry)
}

fn append_manifest_evidence(entry: &mut serde_json::Value, record: &WorkspaceFindingExportRecord) {
    entry["evidenceState"] = json!(record.evidence.state);
    entry["observedEvidencePresent"] = json!(record.evidence.observed_evidence_present);
    entry["observedCodeEvidenceCount"] = json!(record.evidence.observed_code_count);
    entry["observedCaptureEvidenceCount"] = json!(record.evidence.observed_capture_count);
    entry["observedOtherEvidenceCount"] = json!(record.evidence.observed_other_count);
    entry["modelGeneratedReasoningPresent"] =
        json!(record.evidence.model_generated_reasoning_present);
    entry["modelGeneratedReasoningCount"] = json!(record.evidence.model_generated_reasoning_count);
    entry["derivedSourcePresent"] = json!(record.evidence.derived_source_present);
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
