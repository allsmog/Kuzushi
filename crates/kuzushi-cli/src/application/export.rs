use anyhow::{Context, Result};
use kuzushi_core::{
    export_workspace_findings_with_options, preview_workspace_findings_export,
    WorkspaceExportCompleteness, WorkspaceExportFormat, WorkspaceExportOptions, WorkspaceTarget,
};
use std::path::PathBuf;

pub(crate) fn export_command(
    target: PathBuf,
    output: PathBuf,
    format: Option<String>,
    completeness: String,
    preview: bool,
    allow_empty: bool,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let format = resolve_export_format(&output, format.as_deref())?;
    let completeness = WorkspaceExportCompleteness::from_input(&completeness)
        .context("invalid export completeness")?;
    let options = WorkspaceExportOptions::new(Some(format))
        .with_completeness(completeness)
        .with_allow_empty(allow_empty);
    if preview {
        return preview_export_command(&workspace, format, options);
    }
    let output = kuzushi_core::workspace::resolve_contained_output_path(workspace.root(), &output)
        .context("export output must resolve inside the workspace root")?;
    let report = export_workspace_findings_with_options(&workspace, &output, options)?;
    println!(
        "exported {} finding(s) to {} ({}, completeness:{})",
        report.count,
        report.output_path.display(),
        report.format.as_str(),
        completeness.as_str()
    );
    Ok(())
}

fn preview_export_command(
    workspace: &WorkspaceTarget,
    format: WorkspaceExportFormat,
    options: WorkspaceExportOptions,
) -> Result<()> {
    let preview = preview_workspace_findings_export(workspace, format, options)?;
    print!("{}", preview.body);
    Ok(())
}

fn resolve_export_format(
    output: &std::path::Path,
    format: Option<&str>,
) -> Result<WorkspaceExportFormat> {
    format
        .map(WorkspaceExportFormat::from_input)
        .unwrap_or_else(|| WorkspaceExportFormat::from_output_path(output))
        .context("invalid export format")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_output_outside_workspace_is_rejected() {
        let workspace = tempfile::tempdir().unwrap();
        kuzushi_core::WorkspaceTarget::new(workspace.path()).unwrap();

        for output in ["../escape.json", "/tmp/outside-export.json"] {
            let error = export_command(
                workspace.path().to_path_buf(),
                PathBuf::from(output),
                Some("json".to_string()),
                "all".to_string(),
                false,
                true,
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("inside the workspace root"),
                "{output}: {error}"
            );
        }
    }
}
