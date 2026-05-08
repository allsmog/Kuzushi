use super::*;

impl ShellApp {
    pub(crate) fn show_workspace_status(&mut self) {
        self.workspace_view = self.build_workspace_view(None);
        self.shell_view = ShellView::Workspace;
        self.focused_module = Some("workspace".to_string());
        self.log("workspace", self.workspace_view.status.clone());
    }

    pub(crate) fn export_workspace_findings(&mut self, output: &PathBuf) {
        let workspace = match self.explicit_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log("error", error.to_string());
                return;
            }
        };
        let output = if output.is_absolute() {
            output.clone()
        } else {
            workspace.root().join(output)
        };

        match export_workspace_findings(&workspace, &output, None) {
            Ok(report) => {
                self.workspace_view = self.build_workspace_view(Some(report.output_path.clone()));
                self.shell_view = ShellView::Workspace;
                self.focused_module = Some("workspace".to_string());
                self.log(
                    "export",
                    format!(
                        "wrote {} finding(s) to {} ({})",
                        report.count,
                        report.output_path.display(),
                        report.format.as_str()
                    ),
                );
            }
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!("{error}. Next: workspace export findings <path>.json"),
                );
            }
        }
    }

    pub(crate) fn build_workspace_view(&self, last_export: Option<PathBuf>) -> WorkspaceView {
        let Some(target) = self.target.clone() else {
            return WorkspaceView {
                root: None,
                state_dir: None,
                findings_db: None,
                findings_count: None,
                last_export,
                status: "no active workspace. Next: scan <target> or start shell with --target ."
                    .to_string(),
            };
        };

        match WorkspaceTarget::new(&target) {
            Ok(workspace) => {
                let findings_db = workspace.findings_db_path();
                let findings_count = if findings_db.exists() {
                    FindingStore::open(&findings_db)
                        .and_then(|store| store.list_findings(FindingListFilter::MAX_LIMIT))
                        .map(|findings| findings.len())
                        .ok()
                } else {
                    Some(0)
                };
                let count_label = findings_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                WorkspaceView {
                    root: Some(workspace.root().to_path_buf()),
                    state_dir: Some(workspace.state_dir()),
                    findings_db: Some(findings_db),
                    findings_count,
                    last_export,
                    status: format!(
                        "workspace ready; {count_label} finding(s). Next: workspace export findings <path>.json"
                    ),
                }
            }
            Err(error) => WorkspaceView {
                root: None,
                state_dir: None,
                findings_db: None,
                findings_count: None,
                last_export,
                status: format!("{error}. Next: scan <target>"),
            },
        }
    }
}
