use super::*;
use anyhow::Result;
use kuzushi_core::{
    export_workspace_findings, workspace_status_for_target, WorkspaceFindingsExport,
    WorkspaceStatus,
};

pub(crate) fn workspace_for_target(target: Option<&PathBuf>) -> Result<WorkspaceTarget> {
    let target = target.cloned().unwrap_or_else(|| PathBuf::from("."));
    WorkspaceTarget::new(target)
}

pub(crate) fn explicit_workspace_for_target(target: Option<&PathBuf>) -> Result<WorkspaceTarget> {
    let Some(target) = target else {
        anyhow::bail!(
            "workspace export requires an active workspace. Next: scan <target> or start shell with --target ."
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
