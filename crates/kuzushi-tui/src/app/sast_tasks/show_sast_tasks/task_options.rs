use super::*;

impl ShellApp {
    pub(crate) fn current_sast_task_mode(&self) -> SastTaskMode {
        let values = self.option_store.effective_stored_values("sast:scan");
        match values.get("taskMode").and_then(serde_json::Value::as_str) {
            Some("manual") => SastTaskMode::Manual,
            _ => SastTaskMode::Auto,
        }
    }

    pub(crate) fn current_disabled_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store.effective_stored_values("sast:scan");
        read_task_list_value(values.get("disabledTasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    pub(crate) fn current_manual_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store.effective_stored_values("sast:scan");
        read_task_list_value(values.get("tasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    pub(crate) fn manual_tasks_or_current_auto_selection(&self) -> Vec<String> {
        let manual = self.current_manual_sast_tasks();
        if !manual.is_empty() {
            return manual.into_iter().collect();
        }

        let disabled = self.current_disabled_sast_tasks();
        SAST_TASK_CAPABILITIES
            .iter()
            .filter(|task| task.default_enabled && !disabled.contains(task.id))
            .map(|task| task.id.to_string())
            .collect()
    }

    pub(crate) fn write_sast_task_list_option(&mut self, name: &str, values: Vec<String>) {
        let target = OptionTarget::Tool("sast:scan".to_string());
        if values.is_empty() {
            self.option_store
                .unset_value(OptionScope::Session, &target, name);
        } else {
            self.option_store.set_value(
                OptionScope::Session,
                target,
                name,
                serde_json::Value::String(values.join(",")),
            );
        }
    }
}
