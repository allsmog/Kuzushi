use super::*;

impl ShellApp {
    pub(crate) fn show_workspace_status(&mut self) {
        self.workspace_view = self.build_workspace_view(None);
        self.shell_view = ShellView::Workspace;
        self.focused_module = Some("workspace".to_string());
        self.log("workspace", self.workspace_view.status.clone());
    }

    pub(crate) fn export_workspace_findings(&mut self, output: &PathBuf) {
        match export_findings_for_target(self.target.as_ref(), output) {
            Ok(report) => {
                self.workspace_view = self.build_workspace_view(Some(report.output_path.clone()));
                self.shell_view = ShellView::Workspace;
                self.focused_module = Some("workspace".to_string());
                self.log(
                    "export",
                    format!(
                        "wrote {} {} to {} ({})",
                        report.count,
                        if report.count == 1 {
                            "finding"
                        } else {
                            "findings"
                        },
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
        workspace_view_for_target(self.target.as_ref(), last_export)
    }
}
