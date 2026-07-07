use super::*;

impl ShellApp {
    pub(crate) fn plan_sast_task_mode(
        &self,
        mode: SastTaskModeCommand,
    ) -> Result<SastTaskOptionsApply> {
        let next_mode = self.next_sast_task_mode(mode);
        Ok(SastTaskOptionsApply {
            mutations: self.sast_task_mode_mutations(next_mode)?,
            message_prefix: format!("SAST task mode: {}", sast_task_mode_label(next_mode)),
        })
    }

    fn next_sast_task_mode(&self, mode: SastTaskModeCommand) -> SastTaskMode {
        match mode {
            SastTaskModeCommand::Auto => SastTaskMode::Auto,
            SastTaskModeCommand::Manual => SastTaskMode::Manual,
            SastTaskModeCommand::Toggle => toggled_sast_task_mode(self.current_sast_task_mode()),
        }
    }

    fn sast_task_mode_mutations(
        &self,
        next_mode: SastTaskMode,
    ) -> Result<Vec<SastTaskOptionMutation>> {
        match next_mode {
            SastTaskMode::Auto => Ok(vec![
                Self::set_sast_task_option_mutation("taskMode", serde_json::json!("auto")),
                Self::unset_sast_task_option_mutation("tasks"),
            ]),
            SastTaskMode::Manual => {
                let manual = self.manual_tasks_or_current_auto_selection();
                if manual.is_empty() {
                    anyhow::bail!(
                        "manual SAST task mode needs at least one task. Valid task IDs: {}",
                        valid_sast_task_ids().join(", ")
                    );
                }
                Ok(vec![
                    Self::set_sast_task_option_mutation("taskMode", serde_json::json!("manual")),
                    Self::set_sast_task_list_option_mutation("tasks", manual),
                ])
            }
        }
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
