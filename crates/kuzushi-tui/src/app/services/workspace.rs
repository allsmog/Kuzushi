use super::*;
use anyhow::Result;
use kuzushi_core::{
    export_workspace_findings, workspace_status_for_target, WorkspaceFindingsExport,
    WorkspaceStatus,
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
) -> Result<WorkspaceFindingsExport> {
    let workspace = explicit_workspace_for_target(target)?;
    let output = workspace_output_path(&workspace, output);
    export_workspace_findings(&workspace, &output, None)
}

pub(crate) fn workspace_view_for_target(
    target: Option<&PathBuf>,
    last_export: Option<PathBuf>,
) -> WorkspaceView {
    workspace_view_from_status(workspace_status_for_target(
        target.map(PathBuf::as_path),
        last_export,
    ))
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

fn workspace_output_path(workspace: &WorkspaceTarget, output: &PathBuf) -> PathBuf {
    if output.is_absolute() {
        output.clone()
    } else {
        workspace.root().join(output)
    }
}
