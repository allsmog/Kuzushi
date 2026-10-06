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

fn render_bundle_readme_markdown(
    workspace: &WorkspaceTarget,
    records: &[WorkspaceFindingExportRecord],
    options: &WorkspaceExportOptions,
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
    options: &WorkspaceExportOptions,
    total_count: usize,
) {
    out.push_str("# Kuzushi findings bundle\n\n");
    out.push_str(
        "Kuzushi combines scanner output with automated, AI-assisted security analysis. \
         Treat each finding as a review candidate, not as proof by itself.\n\n",
    );
    out.push_str(
        "Proof bands describe evidence: `confirmed` means authenticated runtime reproduction; \
         `likely` means linked static or code evidence; `unverified` has not been promoted beyond \
         a signal; `dismissed` was rejected or suppressed.\n\n",
    );
    out.push_str(&format!(
        "- **Target:** {}\n",
        markdown_code_span(&workspace.root().display().to_string())
    ));
    out.push_str(&format!(
        "- **Finding selection:** `{}`\n",
        options.completeness.as_str()
    ));
    out.push_str(&format!(
        "- **Included:** {} of {} finding(s)\n",
        records.len(),
        total_count
    ));
    out.push_str(
        "- **Field coverage:** human-readable subset; see \
         `manifest.json` → `metadata.omittedFields`\n\n",
    );
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
        "| Alias | Severity | Proof band | Decision | Lifecycle | Evidence | Location |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for record in records {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_table_cell(&record.alias),
            markdown_table_cell(&record.severity),
            markdown_table_cell(&record.proof_confidence),
            markdown_table_cell(&record.review_decision),
            markdown_table_cell(&record.lifecycle_status),
            markdown_table_cell(&record.evidence.state),
            markdown_table_cell(&markdown_code_span(&format!(
                "{}:{}",
                record.location.file, record.location.start_line
            )))
        ));
    }
    if records.is_empty() {
        out.push_str("| - | - | - | - | - | - | - |\n");
    }
    out.push('\n');
}

fn markdown_table_cell(value: &str) -> String {
    markdown_inline_text(value).replace('|', "\\|")
}

/// Finding-derived text placed on a single markdown line (headers, list
/// items). Newlines would let hostile capture content inject its own
/// markdown lines into the bundle.
fn markdown_inline_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('@', "&#64;")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('!', "\\!")
        .replace(['\n', '\r'], " ")
}

fn markdown_code_span(value: &str) -> String {
    let value = value.replace(['\n', '\r'], " ");
    let fence = "`".repeat(longest_backtick_run(&value) + 1);
    format!("{fence}{value}{fence}")
}

/// Wrap finding-derived text in a code fence longer than any backtick run
/// inside it, so snippet content (e.g. a captured HTTP body containing
/// ```` ``` ````) cannot close the fence and inject markdown.
fn fenced_snippet_block(snippet: &str) -> String {
    let snippet = snippet.replace("\r\n", "\n").replace('\r', "\n");
    let fence = "`".repeat(longest_backtick_run(&snippet).max(2) + 1);
    format!("{fence}\n{snippet}\n{fence}\n\n")
}

fn longest_backtick_run(value: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for ch in value.chars() {
        current = if ch == '`' { current + 1 } else { 0 };
        longest = longest.max(current);
    }
    longest
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
    push_bundle_security_context(&mut out, record);
    push_bundle_message(&mut out, finding);
    if !finding.evidence.is_empty() {
        out.push_str("## Evidence\n\n");
        for piece in &finding.evidence {
            push_bundle_evidence(&mut out, piece);
        }
    }
    out
}

fn push_bundle_security_context(out: &mut String, record: &WorkspaceFindingExportRecord) {
    if !has_bundle_security_context(record) {
        return;
    }
    out.push_str("## Security context\n\n");
    push_optional_bundle_field(out, "Recommended change", record.recommendation.as_deref());
    push_optional_bundle_field(out, "Impact", record.impact.as_deref());
    push_optional_bundle_field(out, "Exploit scenario", record.exploit_scenario.as_deref());
    push_optional_bundle_field(out, "Category", record.category.as_deref());
    if record
        .preconditions
        .iter()
        .any(|value| !value.trim().is_empty())
    {
        out.push_str("- **Preconditions:**\n");
        for precondition in record
            .preconditions
            .iter()
            .filter(|value| !value.trim().is_empty())
        {
            out.push_str(&format!("  - {}\n", markdown_inline_text(precondition)));
        }
    }
    out.push('\n');
}

fn has_bundle_security_context(record: &WorkspaceFindingExportRecord) -> bool {
    [
        record.recommendation.as_deref(),
        record.impact.as_deref(),
        record.exploit_scenario.as_deref(),
        record.category.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| !value.trim().is_empty())
        || record
            .preconditions
            .iter()
            .any(|value| !value.trim().is_empty())
}

fn push_optional_bundle_field(out: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        out.push_str(&format!("- **{label}:** {}\n", markdown_inline_text(value)));
    }
}

fn push_bundle_header(out: &mut String, record: &WorkspaceFindingExportRecord) {
    push_bundle_finding_summary(out, record);
    push_bundle_evidence_summary(out, record);
    push_bundle_analysis_summary(out, record);
    out.push_str(&format!(
        "- **Tool:** {}\n",
        markdown_inline_text(&record.tool)
    ));
    out.push_str(&format!(
        "- **Rule:** {}\n",
        markdown_code_span(&record.rule_id)
    ));
    out.push_str(&format!(
        "- **Fingerprint:** {}\n",
        markdown_code_span(&record.fingerprint)
    ));
    push_bundle_run_provenance(out, record);
    push_bundle_remediation(out, record);
    out.push_str(&format!(
        "- **Location:** {}\n\n",
        markdown_code_span(&format!(
            "{}:{}",
            record.location.file, record.location.start_line
        ))
    ));
}

fn push_bundle_finding_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "# {} · {}\n\n",
        record.alias,
        markdown_inline_text(&record.title)
    ));
    out.push_str(&format!(
        "- **Severity:** {}\n",
        markdown_inline_text(&record.severity)
    ));
    out.push_str(&format!(
        "- **Review decision:** {}\n",
        markdown_inline_text(&record.review_decision)
    ));
    push_bundle_decision_basis(out, record);
    if let Some(note) = record.observation_note.as_deref() {
        out.push_str(&format!(
            "- **Observation:** {}\n",
            markdown_inline_text(note)
        ));
    }
    if let Some(conflict) = record.review_decision_conflict.as_deref() {
        out.push_str(&format!(
            "- **Decision conflict:** {}\n",
            markdown_inline_text(conflict)
        ));
    }
    out.push_str(&format!(
        "- **Lifecycle status:** {}\n",
        markdown_inline_text(&record.lifecycle_status)
    ));
}

/// Names the observation a decision was made against, so a later run on
/// different source never silently inherits the verdict.
fn push_bundle_decision_basis(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(basis) = record.review_decision_basis.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Decision basis:** run {} · source snapshot {}\n",
        markdown_code_span(&basis.run_id),
        markdown_code_span(&basis.snapshot_hash)
    ));
    let Some(later) = basis.later_observation.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Seen again after the decision:** run {} · source snapshot {}{}\n",
        markdown_code_span(&later.run_id),
        markdown_code_span(&later.snapshot_hash),
        if basis.source_changed_since_decision {
            " · source changed, so the decision may not describe current code"
        } else {
            " · same source"
        }
    ));
}

fn push_bundle_remediation(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(remediation) = record.remediation.as_ref() else {
        return;
    };
    out.push_str(&format!(
        "- **Remediation:** {} ({})\n",
        markdown_inline_text(&remediation.application_state),
        markdown_code_span(&remediation.application_id)
    ));
    out.push_str(&format!(
        "- **Empirically verified:** {}\n",
        remediation.empirically_verified
    ));
    out.push_str(&format!(
        "- **Patch run:** {} · diff {}\n",
        markdown_code_span(&remediation.patch_run_id),
        markdown_code_span(&remediation.diff_hash)
    ));
    if let Some(outcome) = remediation.reverify_outcome.as_deref() {
        out.push_str(&format!(
            "- **Re-verification:** {}",
            markdown_inline_text(outcome)
        ));
        if let Some(run_id) = remediation.reverify_run_id.as_deref() {
            out.push_str(&format!(" ({})", markdown_code_span(run_id)));
        }
        out.push('\n');
    }
    if !remediation.touched_paths.is_empty() {
        out.push_str(&format!(
            "- **Touched paths:** {}\n",
            remediation
                .touched_paths
                .iter()
                .map(|path| markdown_code_span(path))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn push_bundle_evidence_summary(out: &mut String, record: &WorkspaceFindingExportRecord) {
    out.push_str(&format!(
        "- **Evidence state:** {} ({} observed)\n",
        markdown_inline_text(&record.evidence.state),
        record.evidence.observed_count
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
    out.push_str(&format!(
        "- **Proof band:** {}\n",
        markdown_inline_text(&record.proof_confidence)
    ));
    out.push_str(&format!(
        "- **Static proof:** {} ({})\n",
        markdown_inline_text(&record.static_proof_label),
        markdown_inline_text(&record.static_proof_state)
    ));
    out.push_str(&format!(
        "- **Verification:** {}\n",
        markdown_inline_text(&record.verification.label)
    ));
    if let Some(identity) = &record.verification.source_identity {
        let identity =
            serde_json::to_string(identity).unwrap_or_else(|_| "unavailable".to_string());
        out.push_str(&format!(
            "- **Verification source:** {}\n",
            markdown_code_span(&identity)
        ));
    }
    if let Some(reproducer) = &record.verification.reproducer {
        out.push_str(&format!(
            "- **Verification reproducer:** {} ({})\n",
            markdown_code_span(reproducer.hash.as_str()),
            markdown_inline_text(reproducer.kind.as_str())
        ));
    }
}

fn push_bundle_run_provenance(out: &mut String, record: &WorkspaceFindingExportRecord) {
    let Some(run_id) = record.provenance.run_id.as_deref() else {
        return;
    };
    out.push_str(&format!("- **Run:** {}", markdown_code_span(run_id)));
    if let Some(status) = record.provenance.run_status.as_deref() {
        out.push_str(&format!(" ({})", markdown_inline_text(status)));
    }
    if let Some(model) = record.provenance.model.as_deref() {
        out.push_str(&format!(" model {}", markdown_code_span(model)));
    }
    out.push('\n');
}

fn push_bundle_message(out: &mut String, finding: &Finding) {
    out.push_str("## Message\n\n");
    out.push_str(&fenced_snippet_block(&finding.message));
}

fn push_bundle_evidence(out: &mut String, evidence: &FindingEvidence) {
    out.push_str(&format!(
        "### {kind} · {file}:{line}\n\n",
        kind = markdown_inline_text(&evidence.kind),
        file = markdown_inline_text(&evidence.file_path),
        line = evidence.line
    ));
    out.push_str(&format!(
        "_Origin: {}_\n\n",
        markdown_inline_text(finding_evidence_origin_label(evidence))
    ));
    if !evidence.snippet.is_empty() {
        out.push_str(&fenced_snippet_block(&evidence.snippet));
    }
    if !evidence.rationale.is_empty() {
        out.push_str(&fenced_snippet_block(&evidence.rationale));
    }
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
        "observationGap": record.observation_gap,
        "observationNote": record.observation_note,
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
