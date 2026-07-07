use super::*;

impl ShellApp {
    pub(crate) fn show_sast_tasks(&mut self) {
        if self.registry().resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }
        self.set_focused_module(Some("sast".to_string()));
        self.set_shell_view(ShellView::SastTasks);
        self.log("tasks", self.sast_task_summary_line());
    }

    pub(crate) fn reduce_sast_task_command(
        &mut self,
        command: SastTaskCommand,
    ) -> Vec<ShellEffect> {
        match self.plan_sast_task_command(command) {
            Ok(apply) => vec![ShellEffect::ApplySastTaskOptions(apply)],
            Err(error) => vec![ShellEffect::FinalizeSastTaskCommand(
                SastTaskCommandFinalize {
                    outcome: SastTaskCommandOutcome::Error(error.to_string()),
                },
            )],
        }
    }

    fn plan_sast_task_command(
        &self,
        command: SastTaskCommand,
    ) -> anyhow::Result<SastTaskOptionsApply> {
        self.ensure_sast_module_loaded()?;
        match command {
            SastTaskCommand::Block(raw_id) => self.plan_block_sast_task(&raw_id),
            SastTaskCommand::Allow(raw_id) => self.plan_allow_sast_task(&raw_id),
            SastTaskCommand::Toggle(raw_id) => {
                self.plan_toggle_sast_task(&self.toggle_sast_task_id(raw_id))
            }
            SastTaskCommand::Mode(mode) => self.plan_sast_task_mode(mode),
            SastTaskCommand::Reset => Ok(self.plan_reset_sast_tasks()),
        }
    }

    fn ensure_sast_module_loaded(&self) -> anyhow::Result<()> {
        if self.registry().resolve_tool("sast:scan").is_some() {
            return Ok(());
        }
        anyhow::bail!("SAST module is not loaded. Next: modules");
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

    pub(crate) fn finalize_sast_task_command_effect(&mut self, finalize: SastTaskCommandFinalize) {
        self.set_shell_view(ShellView::SastTasks);
        self.set_focused_module(Some("sast".to_string()));
        match finalize.outcome {
            SastTaskCommandOutcome::Applied(message) => self.log("tasks", message),
            SastTaskCommandOutcome::Error(error) => self.log("error", error),
        }
    }
}
