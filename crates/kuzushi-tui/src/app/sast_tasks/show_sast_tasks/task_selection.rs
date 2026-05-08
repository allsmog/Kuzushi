use super::*;

impl ShellApp {
    pub(crate) fn block_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.insert(task.id.to_string());
        self.write_sast_task_list_option("disabledTasks", disabled.into_iter().collect());

        let mut manual = self.current_manual_sast_tasks();
        manual.remove(task.id);
        self.write_sast_task_list_option("tasks", manual.into_iter().collect());

        Ok(format!(
            "Blocked SAST task capability: {}. {}",
            task.id,
            self.sast_task_summary_line()
        ))
    }

    pub(crate) fn allow_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.remove(task.id);
        self.write_sast_task_list_option("disabledTasks", disabled.into_iter().collect());

        if self.current_sast_task_mode() == SastTaskMode::Manual {
            let mut manual = self.current_manual_sast_tasks();
            manual.insert(task.id.to_string());
            self.write_sast_task_list_option("tasks", manual.into_iter().collect());
        }

        Ok(format!(
            "Allowed SAST task capability: {}. {}",
            task.id,
            self.sast_task_summary_line()
        ))
    }

    pub(crate) fn toggle_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();
        if disabled.contains(task.id)
            || (self.current_sast_task_mode() == SastTaskMode::Manual && !manual.contains(task.id))
        {
            self.allow_sast_task(task.id)
        } else {
            self.block_sast_task(task.id)
        }
    }
    pub(crate) fn reset_sast_tasks(&mut self) -> Result<String> {
        let target = OptionTarget::Tool("sast:scan".to_string());
        for key in ["taskMode", "tasks", "disabledTasks"] {
            self.option_store
                .unset_value(OptionScope::Session, &target, key);
        }
        Ok(format!(
            "SAST task selection reset. {}",
            self.sast_task_summary_line()
        ))
    }
}
