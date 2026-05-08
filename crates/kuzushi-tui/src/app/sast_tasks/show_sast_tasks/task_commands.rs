use super::*;

impl ShellApp {
    pub(crate) fn show_sast_tasks(&mut self) {
        if self.registry.resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }
        self.focused_module = Some("sast".to_string());
        self.shell_view = ShellView::SastTasks;
        self.log("tasks", self.sast_task_summary_line());
    }

    pub(crate) fn handle_sast_task_command(&mut self, command: SastTaskCommand) {
        if !self.ensure_sast_module_loaded() {
            return;
        }
        let result = self.apply_sast_task_command(command);
        self.finish_sast_task_command(result);
    }

    fn ensure_sast_module_loaded(&mut self) -> bool {
        if self.registry.resolve_tool("sast:scan").is_some() {
            return true;
        }
        self.log("error", "SAST module is not loaded. Next: modules");
        false
    }

    fn apply_sast_task_command(&mut self, command: SastTaskCommand) -> anyhow::Result<String> {
        match command {
            SastTaskCommand::Block(raw_id) => self.block_sast_task(&raw_id),
            SastTaskCommand::Allow(raw_id) => self.allow_sast_task(&raw_id),
            SastTaskCommand::Toggle(raw_id) => {
                self.toggle_sast_task(&self.toggle_sast_task_id(raw_id))
            }
            SastTaskCommand::Mode(mode) => self.set_sast_task_mode(mode),
            SastTaskCommand::Reset => self.reset_sast_tasks(),
        }
    }

    fn toggle_sast_task_id(&self, raw_id: Option<String>) -> String {
        raw_id.unwrap_or_else(|| self.default_toggle_sast_task_id())
    }

    fn default_toggle_sast_task_id(&self) -> String {
        self.sast_task_rows()
            .into_iter()
            .find(|row| row.toggleable)
            .map(|row| row.id.to_string())
            .unwrap_or_else(|| "semgrep".to_string())
    }

    fn finish_sast_task_command(&mut self, result: anyhow::Result<String>) {
        self.shell_view = ShellView::SastTasks;
        self.focused_module = Some("sast".to_string());
        match result {
            Ok(message) => self.log("tasks", message),
            Err(error) => self.log("error", error.to_string()),
        }
    }
}
