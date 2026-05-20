use super::*;
use crate::findings::presentation::pr_comment::{build_pr_comment, PrCommentInput};
use crate::findings::{
    format_finding_alias, sorted_finding_aliases, FindingEvidence, Severity,
};
use std::collections::BTreeMap;

pub fn export_workspace_findings(
    workspace: &WorkspaceTarget,
    output_path: impl AsRef<Path>,
    format: Option<WorkspaceExportFormat>,
) -> Result<WorkspaceFindingsExport> {
    let output_path = output_path.as_ref();
    if output_path.as_os_str().is_empty() {
        anyhow::bail!("workspace findings export needs an output path");
    }
    let format = resolve_workspace_findings_export_format(output_path, format)?;
    validate_workspace_findings_output_path(output_path, format)?;
    ensure_workspace_export_parent(output_path)?;

    let store = FindingStore::open(workspace.findings_db_path())?;
    let findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    write_workspace_findings_export(workspace, &findings, format, output_path)?;

    Ok(WorkspaceFindingsExport {
        output_path: output_path.to_path_buf(),
        format,
        count: findings.len(),
    })
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
    format: WorkspaceExportFormat,
    output_path: &Path,
) -> Result<()> {
    if format == WorkspaceExportFormat::MarkdownBundle {
        return write_markdown_bundle(workspace, findings, output_path);
    }
    let body = render_workspace_findings_export(workspace, findings, format)?;
    fs::write(output_path, body)
        .with_context(|| format!("Could not write {}", output_path.display()))
}

fn render_workspace_findings_export(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    format: WorkspaceExportFormat,
) -> Result<String> {
    match format {
        WorkspaceExportFormat::Json => workspace_findings_to_json(workspace, findings),
        WorkspaceExportFormat::Jsonl => findings_to_jsonl(findings),
        WorkspaceExportFormat::Sarif => findings_to_sarif(workspace, findings),
        WorkspaceExportFormat::Csv => findings_to_csv(findings),
        WorkspaceExportFormat::MarkdownBundle => {
            anyhow::bail!("markdown-bundle is a directory output; routed via write_markdown_bundle")
        }
    }
}

fn workspace_findings_to_json(workspace: &WorkspaceTarget, findings: &[Finding]) -> Result<String> {
    Ok(serde_json::to_string_pretty(&json!({
        "format": "kuzushi.workspace.findings.v1",
        "workspaceRoot": workspace.root().display().to_string(),
        "findingsDb": workspace.findings_db_path().display().to_string(),
        "count": findings.len(),
        "findings": findings,
    }))?)
}

pub(crate) fn findings_to_jsonl(findings: &[Finding]) -> Result<String> {
    let mut lines = String::new();
    for finding in findings {
        lines.push_str(&serde_json::to_string(finding)?);
        lines.push('\n');
    }
    Ok(lines)
}

const KUZUSHI_INFORMATION_URI: &str = "https://github.com/allsmog/Kuzushi";

pub(crate) fn findings_to_sarif(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
) -> Result<String> {
    let runs = group_findings_by_tool(findings)
        .into_iter()
        .map(|(tool, tool_findings)| build_sarif_run(&tool, &tool_findings, workspace))
        .collect::<Vec<_>>();
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

fn group_findings_by_tool(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut grouped: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        grouped.entry(finding.tool.clone()).or_default().push(finding);
    }
    grouped
}

fn build_sarif_run(
    tool: &str,
    findings: &[&Finding],
    workspace: &WorkspaceTarget,
) -> serde_json::Value {
    let rules = sarif_rules(findings);
    let results = findings
        .iter()
        .map(|finding| sarif_result(finding))
        .collect::<Vec<_>>();
    json!({
        "tool": {
            "driver": {
                "name": tool,
                "informationUri": KUZUSHI_INFORMATION_URI,
                "rules": rules,
            }
        },
        "originalUriBaseIds": {
            "WORKSPACE_ROOT": {
                "uri": format!("file://{}/", workspace.root().display()),
            }
        },
        "results": results,
    })
}

fn sarif_rules(findings: &[&Finding]) -> Vec<serde_json::Value> {
    let mut rules: BTreeMap<&str, &Finding> = BTreeMap::new();
    for finding in findings {
        rules.entry(finding.rule_id.as_str()).or_insert(finding);
    }
    rules
        .values()
        .map(|finding| {
            json!({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": { "text": finding.title },
                "fullDescription": { "text": finding.message },
                "defaultConfiguration": { "level": sarif_level(finding.severity) },
            })
        })
        .collect()
}

fn sarif_result(finding: &Finding) -> serde_json::Value {
    json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": { "text": finding.message },
        "fingerprints": { "kuzushi/v1": finding.fingerprint },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file_path,
                    "uriBaseId": "WORKSPACE_ROOT",
                },
                "region": sarif_region(finding),
            }
        }],
    })
}

fn sarif_region(finding: &Finding) -> serde_json::Value {
    let mut region = json!({ "startLine": finding.start_line.max(1) });
    if let Some(end_line) = finding.end_line {
        region["endLine"] = json!(end_line.max(finding.start_line));
    }
    region
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info | Severity::Unknown => "note",
    }
}

pub(crate) fn findings_to_csv(findings: &[Finding]) -> Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::<u8>::new());
    writer.write_record([
        "fingerprint",
        "rule_id",
        "title",
        "severity",
        "tool",
        "file",
        "start_line",
        "end_line",
        "message",
    ])?;
    for finding in findings {
        writer.write_record(csv_finding_row(finding))?;
    }
    let bytes = writer
        .into_inner()
        .context("Could not finalize CSV export buffer")?;
    String::from_utf8(bytes).context("CSV export produced non-UTF-8 output")
}

fn csv_finding_row(finding: &Finding) -> [String; 9] {
    [
        finding.fingerprint.clone(),
        finding.rule_id.clone(),
        finding.title.clone(),
        finding.severity.as_str().to_string(),
        finding.tool.clone(),
        finding.file_path.clone(),
        finding.start_line.to_string(),
        finding
            .end_line
            .map(|n| n.to_string())
            .unwrap_or_default(),
        finding.message.clone(),
    ]
}

fn write_markdown_bundle(
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
    out.push_str(&format!("# {alias} · {}\n\n", finding.title));
    out.push_str(&format!("- **Severity:** {}\n", finding.severity.as_str()));
    out.push_str(&format!("- **Tool:** {}\n", finding.tool));
    out.push_str(&format!("- **Rule:** `{}`\n", finding.rule_id));
    out.push_str(&format!("- **Fingerprint:** `{}`\n", finding.fingerprint));
    out.push_str(&format!(
        "- **Location:** `{}:{}`\n\n",
        finding.file_path, finding.start_line
    ));
    out.push_str("## Message\n\n");
    out.push_str(&finding.message);
    out.push_str("\n\n");
    if !finding.evidence.is_empty() {
        out.push_str("## Evidence\n\n");
        for piece in &finding.evidence {
            push_bundle_evidence(&mut out, piece);
        }
    }
    out
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
        .map(|(index, (alias, finding))| {
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
        })
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
