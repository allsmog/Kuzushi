use super::*;

impl ShellApp {
    pub(crate) fn reduce_workspace_command_effects(
        &mut self,
        command: &WorkspaceCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            WorkspaceCommand::Status => Some(vec![ShellEffect::ShowWorkspaceStatus]),
            WorkspaceCommand::ScopeInit => {
                Some(vec![ShellEffect::WorkspaceScopeInit(WorkspaceScopeInit {
                    target: self.target_owned(),
                })])
            }
            WorkspaceCommand::ExportFindings {
                output,
                format,
                completeness,
                allow_empty,
            } => Some(vec![ShellEffect::WorkspaceExportFindings(
                WorkspaceExportFindings {
                    allow_empty: *allow_empty,
                    completeness: completeness.clone(),
                    format: format.clone(),
                    output: output.clone(),
                    target: self.target_owned(),
                },
            )]),
            WorkspaceCommand::Unsupported(raw) => {
                self.show_unsupported_workspace_command(raw);
                Some(Vec::new())
            }
        }
    }

    fn show_unsupported_workspace_command(&mut self, raw: &str) {
        self.set_shell_view(ShellView::Workspace);
        self.log(
            "error",
            format!(
                "{raw} is not supported by the Rust workspace bridge yet. Supported: workspace status, workspace scope init, workspace export findings <path> [json|jsonl|sarif|csv|markdown-bundle] [--completeness open|complete] [--allow-empty]"
            ),
        );
    }

    pub(crate) fn show_history(&mut self) {
        self.set_shell_view(ShellView::History);
        self.router.history_mut().open();
        let count = self.command_history().len();
        self.log(
            "history",
            format!(
                "showing {count} {}. Next: clear or run <tool>",
                if count == 1 { "command" } else { "commands" }
            ),
        );
    }

    pub(crate) fn clear_conversation(&mut self) {
        self.jobs_mut().cancel(JobKind::Agent);
        self.jobs_mut().finish(JobKind::Agent);
        self.clear_log();
        *self.selected_finding_mut() = None;
        self.clear_agent_chat();
        self.set_agent_cancel(None);
        self.set_shell_view(ShellView::Catalog);
        self.log(
            "system",
            "Conversation cleared. Command history retained. Next: history or help",
        );
    }
}
