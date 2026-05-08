use super::*;

impl ShellApp {
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
}
