use super::*;

impl ShellApp {
    pub(crate) fn current_sast_task_mode(&self) -> SastTaskMode {
        let values = self.option_store().effective_stored_values("sast:scan");
        match values.get("taskMode").and_then(serde_json::Value::as_str) {
            Some("manual") => SastTaskMode::Manual,
            _ => SastTaskMode::Auto,
        }
    }

    pub(crate) fn current_disabled_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store().effective_stored_values("sast:scan");
        read_task_list_value(values.get("disabledTasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    pub(crate) fn current_manual_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store().effective_stored_values("sast:scan");
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

    pub(crate) fn apply_sast_task_options_effect(
        &mut self,
        apply: SastTaskOptionsApply,
    ) -> Vec<ShellEffect> {
        for mutation in apply.mutations {
            self.apply_sast_task_option_mutation(mutation);
        }
        vec![ShellEffect::FinalizeSastTaskCommand(
            SastTaskCommandFinalize {
                outcome: SastTaskCommandOutcome::Applied(format!(
                    "{}. {}",
                    apply.message_prefix,
                    self.sast_task_summary_line()
                )),
            },
        )]
    }

    fn apply_sast_task_option_mutation(&mut self, mutation: SastTaskOptionMutation) {
        let target = OptionTarget::Tool("sast:scan".to_string());
        match mutation {
            SastTaskOptionMutation::Set { name, value } => {
                self.option_store_mut()
                    .set_value(OptionScope::Session, target, name, value);
            }
            SastTaskOptionMutation::Unset { name } => {
                self.option_store_mut()
                    .unset_value(OptionScope::Session, &target, &name);
            }
        }
    }

    pub(crate) fn set_sast_task_option_mutation(
        name: &str,
        value: serde_json::Value,
    ) -> SastTaskOptionMutation {
        SastTaskOptionMutation::Set {
            name: name.to_string(),
            value,
        }
    }

    pub(crate) fn unset_sast_task_option_mutation(name: &str) -> SastTaskOptionMutation {
        SastTaskOptionMutation::Unset {
            name: name.to_string(),
        }
    }

    pub(crate) fn set_sast_task_list_option_mutation(
        name: &str,
        values: Vec<String>,
    ) -> SastTaskOptionMutation {
        if values.is_empty() {
            return Self::unset_sast_task_option_mutation(name);
        }
        Self::set_sast_task_option_mutation(name, serde_json::Value::String(values.join(",")))
    }
}
