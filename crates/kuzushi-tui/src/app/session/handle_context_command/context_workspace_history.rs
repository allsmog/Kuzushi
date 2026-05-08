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
        match command {
            WorkspaceCommand::Status => self.show_workspace_status(),
            WorkspaceCommand::ExportFindings { output } => self.export_workspace_findings(&output),
            WorkspaceCommand::Unsupported(raw) => {
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!(
                        "{raw} is not supported by the Rust workspace bridge yet. Supported: workspace status, workspace export findings <path>.json"
                    ),
                );
            }
        }
    }

    pub(crate) fn show_history(&mut self) {
        self.shell_view = ShellView::History;
        self.history_scroll = 0;
        self.log(
            "history",
            format!(
                "showing {} command(s). Next: clear or run <tool>",
                self.command_history.len()
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
