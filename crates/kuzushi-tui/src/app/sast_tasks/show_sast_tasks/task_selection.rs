use super::*;

impl ShellApp {
    pub(crate) fn plan_block_sast_task(&self, raw_id: &str) -> Result<SastTaskOptionsApply> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.insert(task.id.to_string());

        let mut manual = self.current_manual_sast_tasks();
        manual.remove(task.id);

        Ok(SastTaskOptionsApply {
            mutations: vec![
                Self::set_sast_task_list_option_mutation(
                    "disabledTasks",
                    disabled.into_iter().collect(),
                ),
                Self::set_sast_task_list_option_mutation("tasks", manual.into_iter().collect()),
            ],
            message_prefix: format!("Blocked SAST task capability: {}", task.id),
        })
    }

    pub(crate) fn plan_allow_sast_task(&self, raw_id: &str) -> Result<SastTaskOptionsApply> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.remove(task.id);
        let mut mutations = vec![Self::set_sast_task_list_option_mutation(
            "disabledTasks",
            disabled.into_iter().collect(),
        )];

        if self.current_sast_task_mode() == SastTaskMode::Manual {
            let mut manual = self.current_manual_sast_tasks();
            manual.insert(task.id.to_string());
            mutations.push(Self::set_sast_task_list_option_mutation(
                "tasks",
                manual.into_iter().collect(),
            ));
        }

        Ok(SastTaskOptionsApply {
            mutations,
            message_prefix: format!("Allowed SAST task capability: {}", task.id),
        })
    }

    pub(crate) fn plan_toggle_sast_task(&self, raw_id: &str) -> Result<SastTaskOptionsApply> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();
        if disabled.contains(task.id)
            || (self.current_sast_task_mode() == SastTaskMode::Manual && !manual.contains(task.id))
        {
            self.plan_allow_sast_task(task.id)
        } else {
            self.plan_block_sast_task(task.id)
        }
    }

    pub(crate) fn plan_reset_sast_tasks(&self) -> SastTaskOptionsApply {
        SastTaskOptionsApply {
            mutations: ["taskMode", "tasks", "disabledTasks"]
                .into_iter()
                .map(Self::unset_sast_task_option_mutation)
                .collect(),
            message_prefix: "SAST task selection reset".to_string(),
        }
    }
}
