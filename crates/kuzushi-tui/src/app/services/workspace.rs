use super::*;
use anyhow::Result;
use kuzushi_core::workspace::write_program_scope_scaffold;
use kuzushi_core::{
    export_workspace_findings_with_options,
    incremental_index::{WorkspaceChange, WorkspaceIndexUpdate},
    workspace_status_for_target, WorkspaceExportCompleteness, WorkspaceExportFormat,
    WorkspaceExportOptions, WorkspaceFindingsExport, WorkspaceStatus,
};

pub(crate) fn workspace_for_target(target: Option<&PathBuf>) -> Result<WorkspaceTarget> {
    // No silent cwd fallback. Bug-bounty operators need scope discipline,
    // so the dangerous `Some(PathBuf::from("."))` default has been replaced
    // with an actionable error. To intentionally operate on the current
    // directory pass `--target .` at launch or run `target .` in the shell.
    explicit_workspace_for_target(target)
}

pub(crate) fn explicit_workspace_for_target(target: Option<&PathBuf>) -> Result<WorkspaceTarget> {
    let Some(target) = target else {
        anyhow::bail!(
            "no target set. Next: `target <path>` (or `target .` to use the current directory). \
             From the CLI pass `--target <path>` (or `--target .`)."
        );
    };
    WorkspaceTarget::new(target)
}

pub(crate) fn export_findings_for_target(
    target: Option<&PathBuf>,
    output: &PathBuf,
    format: Option<&str>,
    completeness: Option<&str>,
    allow_empty: bool,
) -> Result<WorkspaceFindingsExport> {
    let workspace = explicit_workspace_for_target(target)?;
    let output = workspace_output_path(&workspace, output)?;
    let format = format.map(WorkspaceExportFormat::from_input).transpose()?;
    let completeness = completeness
        .map(WorkspaceExportCompleteness::from_input)
        .transpose()?
        .unwrap_or_default();
    let options = WorkspaceExportOptions::new(format)
        .with_completeness(completeness)
        .with_allow_empty(allow_empty);
    export_workspace_findings_with_options(&workspace, &output, options)
}

pub(crate) fn init_scope_for_target(target: Option<&PathBuf>) -> Result<PathBuf> {
    let workspace = explicit_workspace_for_target(target)?;
    write_program_scope_scaffold(&workspace)
}

pub(crate) fn reindex_workspace_for_target(
    target: Option<&PathBuf>,
    changes: &[WorkspaceChange],
) -> Result<WorkspaceIndexUpdate> {
    let workspace = explicit_workspace_for_target(target)?;
    if changes.is_empty() {
        return kuzushi_core::incremental_index::index_workspace_snapshot(&workspace)
            .map(WorkspaceIndexUpdate::Full);
    }
    kuzushi_core::incremental_index::index_workspace_changes(&workspace, changes)
}

pub(crate) fn workspace_view_for_target(
    target: Option<&PathBuf>,
    last_export: Option<PathBuf>,
) -> WorkspaceView {
    let mut view = workspace_view_from_status(workspace_status_for_target(
        target.map(PathBuf::as_path),
        last_export,
    ));
    if view.root.is_none() {
        view.status = shell_workspace_recovery(&view.status);
    }
    view
}

fn shell_workspace_recovery(status: &str) -> String {
    let detail = status
        .split_once(". Next:")
        .map_or(status, |(detail, _)| detail)
        .trim_end_matches('.');
    format!("{detail}. Next: target <path>, then map; or full <path>")
}

fn workspace_view_from_status(status: WorkspaceStatus) -> WorkspaceView {
    WorkspaceView {
        root: status.root,
        state_dir: status.state_dir,
        findings_db: status.findings_db,
        findings_count: status.findings_count,
        last_export: status.last_export,
        status: status.status,
    }
}

fn workspace_output_path(workspace: &WorkspaceTarget, output: &PathBuf) -> Result<PathBuf> {
    kuzushi_core::workspace::resolve_contained_output_path(workspace.root(), output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_workspace_preserves_error_and_projects_shell_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing-target");

        let view = workspace_view_for_target(Some(&missing), None);

        assert!(view.root.is_none());
        assert!(view.status.contains("Target path does not exist"));
        assert!(view
            .status
            .contains("Next: target <path>, then map; or full <path>"));
        assert!(!view.status.contains("kuzushi scan <target>"));
    }
}
