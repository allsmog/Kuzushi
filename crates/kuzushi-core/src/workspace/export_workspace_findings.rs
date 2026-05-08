use super::*;

pub fn export_workspace_findings(
    workspace: &WorkspaceTarget,
    output_path: impl AsRef<Path>,
    format: Option<WorkspaceExportFormat>,
) -> Result<WorkspaceFindingsExport> {
    let output_path = output_path.as_ref();
    validate_workspace_findings_output_path(output_path)?;
    let format = resolve_workspace_findings_export_format(output_path, format)?;
    ensure_workspace_export_parent(output_path)?;

    let store = FindingStore::open(workspace.findings_db_path())?;
    let findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    let body = render_workspace_findings_export(workspace, &findings, format)?;
    fs::write(output_path, body)
        .with_context(|| format!("Could not write {}", output_path.display()))?;

    Ok(WorkspaceFindingsExport {
        output_path: output_path.to_path_buf(),
        format,
        count: findings.len(),
    })
}

fn validate_workspace_findings_output_path(output_path: &Path) -> Result<()> {
    if output_path.as_os_str().is_empty() {
        anyhow::bail!("workspace findings export needs an output path");
    }
    if output_path.exists() && output_path.is_dir() {
        anyhow::bail!(
            "workspace findings export output must be a file path, not directory: {}",
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

fn render_workspace_findings_export(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    format: WorkspaceExportFormat,
) -> Result<String> {
    match format {
        WorkspaceExportFormat::Json => workspace_findings_to_json(workspace, findings),
        WorkspaceExportFormat::Jsonl => findings_to_jsonl(findings),
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
