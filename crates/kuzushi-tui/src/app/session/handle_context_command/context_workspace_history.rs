use super::*;

impl ShellApp {
    pub(crate) fn handle_context_command(&mut self, command: ContextCommand) {
        match command {
            ContextCommand::Show | ContextCommand::Status => self.show_context_status(),
            ContextCommand::Build => self.build_context_snapshot(None),
            ContextCommand::Regen(slice) => self.regen_context_slice(&slice),
        }
    }

    pub(crate) fn handle_workspace_command(&mut self, command: WorkspaceCommand) {
        if let Some(effects) = self.reduce_workspace_command_effects(&command) {
            self.execute_effects(effects);
            return;
        }
        match command {
            WorkspaceCommand::Status => self.show_workspace_status(),
            WorkspaceCommand::Unsupported(raw) => {
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!(
                        "{raw} is not supported by the Rust workspace bridge yet. Supported: workspace status, workspace scope init, workspace export findings <path> [json|jsonl|sarif|csv|markdown-bundle] [--completeness open|complete] [--allow-empty]"
                    ),
                );
            }
            WorkspaceCommand::ScopeInit | WorkspaceCommand::ExportFindings { .. } => {}
        }
    }

    pub(crate) fn reduce_workspace_command_effects(
        &mut self,
        command: &WorkspaceCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            WorkspaceCommand::ScopeInit => {
                Some(vec![ShellEffect::WorkspaceScopeInit(WorkspaceScopeInit {
                    target: self.target.clone(),
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
                    target: self.target.clone(),
                },
            )]),
            WorkspaceCommand::Status | WorkspaceCommand::Unsupported(_) => None,
        }
    }

    pub(crate) fn show_history(&mut self) {
        self.shell_view = ShellView::History;
        self.router.history_mut().open();
        let count = self.command_history.len();
        self.log(
            "history",
            format!(
                "showing {count} {}. Next: clear or run <tool>",
                if count == 1 { "command" } else { "commands" }
            ),
        );
    }

    pub(crate) fn clear_conversation(&mut self) {
        self.log.clear();
        self.selected_finding = None;
        self.agent_chat = None;
        self.agent_rx = None;
        self.shell_view = ShellView::Catalog;
        self.log(
            "system",
            "Conversation cleared. Command history retained. Next: history or help",
        );
    }
}
