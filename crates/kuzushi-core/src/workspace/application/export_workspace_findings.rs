use super::export_markdown_bundle::write_markdown_bundle;
use super::export_sarif::findings_to_sarif;
use super::*;

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
        "source_signature",
        "corroboration_count",
        "triaged_by",
        "sources",
    ])?;
    for finding in findings {
        writer.write_record(csv_finding_row(finding))?;
    }
    let bytes = writer
        .into_inner()
        .context("Could not finalize CSV export buffer")?;
    String::from_utf8(bytes).context("CSV export produced non-UTF-8 output")
}

fn csv_finding_row(finding: &Finding) -> [String; 13] {
    [
        finding.fingerprint.clone(),
        finding.rule_id.clone(),
        finding.title.clone(),
        finding.severity.as_str().to_string(),
        finding.tool.clone(),
        finding.file_path.clone(),
        finding.start_line.to_string(),
        finding.end_line.map(|n| n.to_string()).unwrap_or_default(),
        finding.message.clone(),
        finding.source_signature.clone().unwrap_or_default(),
        finding.corroboration_count.to_string(),
        finding
            .triaged_by
            .map(|author| author.as_str().to_string())
            .unwrap_or_default(),
        finding_source_list(finding),
    ]
}

fn finding_source_list(finding: &Finding) -> String {
    finding
        .sources
        .iter()
        .map(|source| format!("{}:{}", source.tool, source.source_signature))
        .collect::<Vec<_>>()
        .join(";")
}
