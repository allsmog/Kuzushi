//! M1 §1.4 — markdown bundle export. Output is a directory containing
//! `README.md` (the PR-comment markdown), per-finding `.md` files, and
//! `manifest.json`. Lives in its own module to keep
//! `export_workspace_findings.rs` under the 300-line per-file limit
//! enforced by the CRAP-risk gate.

use super::*;
use crate::findings::presentation::pr_comment::{build_pr_comment, PrCommentInput};
use crate::findings::{format_finding_alias, sorted_finding_aliases, FindingEvidence};

pub(crate) fn write_markdown_bundle(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    output_dir: &Path,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;
    let findings_dir = output_dir.join("findings");
    fs::create_dir_all(&findings_dir)
        .with_context(|| format!("Could not create {}", findings_dir.display()))?;

    let aliased = sorted_finding_aliases(findings);
    write_bundle_readme(workspace, findings, output_dir)?;
    write_bundle_finding_files(&aliased, &findings_dir)?;
    write_bundle_manifest(workspace, &aliased, output_dir)
}

fn write_bundle_readme(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    output_dir: &Path,
) -> Result<()> {
    let repo_name = workspace
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string);
    let input = PrCommentInput {
        repo_name,
        findings: findings.to_vec(),
        ..Default::default()
    };
    let body = build_pr_comment(&input);
    let readme = format!("# Kuzushi findings bundle\n\n{body}\n");
    let path = output_dir.join("README.md");
    fs::write(&path, readme).with_context(|| format!("Could not write {}", path.display()))
}

fn write_bundle_finding_files(
    aliased: &[(String, Finding)],
    findings_dir: &Path,
) -> Result<()> {
    for (alias, finding) in aliased {
        let body = render_bundle_finding_markdown(alias, finding);
        let path = findings_dir.join(format!("{alias}.md"));
        fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))?;
    }
    Ok(())
}

fn render_bundle_finding_markdown(alias: &str, finding: &Finding) -> String {
    let mut out = String::new();
    push_bundle_header(&mut out, alias, finding);
    push_bundle_message(&mut out, finding);
    if !finding.evidence.is_empty() {
        out.push_str("## Evidence\n\n");
        for piece in &finding.evidence {
            push_bundle_evidence(&mut out, piece);
        }
    }
    out
}

fn push_bundle_header(out: &mut String, alias: &str, finding: &Finding) {
    out.push_str(&format!("# {alias} · {}\n\n", finding.title));
    out.push_str(&format!("- **Severity:** {}\n", finding.severity.as_str()));
    out.push_str(&format!("- **Tool:** {}\n", finding.tool));
    out.push_str(&format!("- **Rule:** `{}`\n", finding.rule_id));
    out.push_str(&format!("- **Fingerprint:** `{}`\n", finding.fingerprint));
    out.push_str(&format!(
        "- **Location:** `{}:{}`\n\n",
        finding.file_path, finding.start_line
    ));
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
    aliased: &[(String, Finding)],
    output_dir: &Path,
) -> Result<()> {
    let entries = aliased
        .iter()
        .enumerate()
        .map(|(index, (alias, finding))| build_manifest_entry(index, alias, finding))
        .collect::<Vec<_>>();
    let document = json!({
        "format": "kuzushi.workspace.findings-bundle.v1",
        "workspaceRoot": workspace.root().display().to_string(),
        "count": aliased.len(),
        "findings": entries,
    });
    let path = output_dir.join("manifest.json");
    fs::write(&path, serde_json::to_string_pretty(&document)?)
        .with_context(|| format!("Could not write {}", path.display()))
}

fn build_manifest_entry(index: usize, alias: &str, finding: &Finding) -> serde_json::Value {
    let canonical_alias = format_finding_alias(index);
    json!({
        "alias": alias,
        "canonicalAlias": canonical_alias,
        "fingerprint": finding.fingerprint,
        "severity": finding.severity.as_str(),
        "tool": finding.tool,
        "ruleId": finding.rule_id,
        "file": finding.file_path,
        "startLine": finding.start_line,
        "path": format!("findings/{alias}.md"),
    })
}
