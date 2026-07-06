use super::*;

impl ShellApp {
    pub(crate) fn show_workspace_status(&mut self) {
        self.workspace_view = self.build_workspace_view(None);
        self.shell_view = ShellView::Workspace;
        self.focused_module = Some("workspace".to_string());
        self.log("workspace", self.workspace_view.status.clone());
    }

    pub(crate) fn build_workspace_view(&self, last_export: Option<PathBuf>) -> WorkspaceView {
        workspace_view_for_target(self.target.as_ref(), last_export)
    }
}

pub(crate) fn workspace_export_message(
    report: &kuzushi_core::WorkspaceFindingsExport,
    completeness: Option<&str>,
) -> String {
    let base = format!(
        "wrote {} {} to {} ({}) completeness:{}",
        report.count,
        if report.count == 1 {
            "finding"
        } else {
            "findings"
        },
        report.output_path.display(),
        report.format.as_str(),
        completeness.unwrap_or("all")
    );
    if report.format == kuzushi_core::WorkspaceExportFormat::MarkdownBundle {
        return format!(
            "{base} · open {}",
            report.output_path.join("README.md").display()
        );
    }
    base
}
