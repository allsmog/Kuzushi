use super::*;

impl ShellApp {
    pub(crate) fn set_sast_task_mode(&mut self, mode: SastTaskModeCommand) -> Result<String> {
        let next_mode = self.next_sast_task_mode(mode);
        self.apply_sast_task_mode(next_mode)?;
        Ok(format!(
            "SAST task mode: {}. {}",
            sast_task_mode_label(next_mode),
            self.sast_task_summary_line()
        ))
    }

    fn next_sast_task_mode(&self, mode: SastTaskModeCommand) -> SastTaskMode {
        match mode {
            SastTaskModeCommand::Auto => SastTaskMode::Auto,
            SastTaskModeCommand::Manual => SastTaskMode::Manual,
            SastTaskModeCommand::Toggle => toggled_sast_task_mode(self.current_sast_task_mode()),
        }
    }

    fn apply_sast_task_mode(&mut self, next_mode: SastTaskMode) -> Result<()> {
        match next_mode {
            SastTaskMode::Auto => {
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Tool("sast:scan".to_string()),
                    "taskMode",
                    serde_json::json!("auto"),
                );
                self.option_store.unset_value(
                    OptionScope::Session,
                    &OptionTarget::Tool("sast:scan".to_string()),
                    "tasks",
                );
            }
            SastTaskMode::Manual => {
                let manual = self.manual_tasks_or_current_auto_selection();
                if manual.is_empty() {
                    anyhow::bail!(
                        "manual SAST task mode needs at least one task. Valid task IDs: {}",
                        valid_sast_task_ids().join(", ")
                    );
                }
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Tool("sast:scan".to_string()),
                    "taskMode",
                    serde_json::json!("manual"),
                );
                self.write_sast_task_list_option("tasks", manual);
            }
        }
        Ok(())
    }
}

fn toggled_sast_task_mode(current: SastTaskMode) -> SastTaskMode {
    match current {
        SastTaskMode::Auto => SastTaskMode::Manual,
        SastTaskMode::Manual => SastTaskMode::Auto,
    }
}

fn sast_task_mode_label(mode: SastTaskMode) -> &'static str {
    match mode {
        SastTaskMode::Auto => "auto + denylist",
        SastTaskMode::Manual => "manual allowlist",
    }
}
