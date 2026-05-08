use super::prelude::*;
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
    if output_path.exists() && output_path.is_dir() {
        anyhow::bail!(
            "workspace findings export output must be a file path, not directory: {}",
            output_path.display()
        );
    }

    let format = match format {
        Some(format) => format,
        None => WorkspaceExportFormat::from_output_path(output_path)?,
    };
    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }

    let store = FindingStore::open(workspace.findings_db_path())?;
    let findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    let body = match format {
        WorkspaceExportFormat::Json => serde_json::to_string_pretty(&json!({
            "format": "kuzushi.workspace.findings.v1",
            "workspaceRoot": workspace.root().display().to_string(),
            "findingsDb": workspace.findings_db_path().display().to_string(),
            "count": findings.len(),
            "findings": &findings,
        }))?,
        WorkspaceExportFormat::Jsonl => findings_to_jsonl(&findings)?,
    };
    fs::write(output_path, body)
        .with_context(|| format!("Could not write {}", output_path.display()))?;

    Ok(WorkspaceFindingsExport {
        output_path: output_path.to_path_buf(),
        format,
        count: findings.len(),
    })
}

pub(crate) fn findings_to_jsonl(findings: &[Finding]) -> Result<String> {
    let mut lines = String::new();
    for finding in findings {
        lines.push_str(&serde_json::to_string(finding)?);
        lines.push('\n');
    }
    Ok(lines)
}
