use super::prelude::*;
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
        if self.registry.resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }

        let result = match command {
            SastTaskCommand::Block(raw_id) => self.block_sast_task(&raw_id),
            SastTaskCommand::Allow(raw_id) => self.allow_sast_task(&raw_id),
            SastTaskCommand::Toggle(raw_id) => {
                let raw_id = raw_id.unwrap_or_else(|| {
                    self.sast_task_rows()
                        .into_iter()
                        .find(|row| row.toggleable)
                        .map(|row| row.id.to_string())
                        .unwrap_or_else(|| "semgrep".to_string())
                });
                self.toggle_sast_task(&raw_id)
            }
            SastTaskCommand::Mode(mode) => self.set_sast_task_mode(mode),
            SastTaskCommand::Reset => self.reset_sast_tasks(),
        };

        self.shell_view = ShellView::SastTasks;
        self.focused_module = Some("sast".to_string());
        match result {
            Ok(message) => self.log("tasks", message),
            Err(error) => self.log("error", error.to_string()),
        }
    }

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

    pub(crate) fn set_sast_task_mode(&mut self, mode: SastTaskModeCommand) -> Result<String> {
        let next_mode = match mode {
            SastTaskModeCommand::Auto => SastTaskMode::Auto,
            SastTaskModeCommand::Manual => SastTaskMode::Manual,
            SastTaskModeCommand::Toggle => match self.current_sast_task_mode() {
                SastTaskMode::Auto => SastTaskMode::Manual,
                SastTaskMode::Manual => SastTaskMode::Auto,
            },
        };

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

        Ok(format!(
            "SAST task mode: {}. {}",
            match next_mode {
                SastTaskMode::Auto => "auto + denylist",
                SastTaskMode::Manual => "manual allowlist",
            },
            self.sast_task_summary_line()
        ))
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

    pub(crate) fn sast_task_rows(&self) -> Vec<SastTaskRow> {
        let mode = self.current_sast_task_mode();
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();

        SAST_TASK_CAPABILITIES
            .iter()
            .map(|task| {
                let blocked = disabled.contains(task.id);
                let selected = if blocked {
                    false
                } else if mode == SastTaskMode::Manual {
                    manual.contains(task.id)
                } else {
                    task.default_enabled
                };
                let state = if blocked {
                    "[ ]"
                } else if selected {
                    "[x]"
                } else {
                    "[A]"
                };
                let source = if blocked {
                    "blocked"
                } else if mode == SastTaskMode::Manual {
                    "manual"
                } else if task.default_enabled {
                    "default"
                } else {
                    "available"
                };
                SastTaskRow {
                    id: task.id,
                    scan_task: task.scan_task,
                    cost: task.cost,
                    notes: task.notes,
                    toggleable: task.toggleable,
                    selected,
                    state,
                    source,
                }
            })
            .collect()
    }

    pub(crate) fn sast_task_summary_line(&self) -> String {
        let rows = self.sast_task_rows();
        let enabled = rows.iter().filter(|row| row.selected).count();
        let blocked = rows.iter().filter(|row| row.source == "blocked").count();
        let mode = match self.current_sast_task_mode() {
            SastTaskMode::Auto => "auto + denylist",
            SastTaskMode::Manual => "manual allowlist",
        };
        format!(
            "{mode}; {enabled}/{} enabled; {blocked} blocked. Next: /task toggle <id> or /scan",
            rows.len()
        )
    }

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
