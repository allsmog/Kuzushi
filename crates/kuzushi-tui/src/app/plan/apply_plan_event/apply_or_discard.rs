use super::*;

impl ShellApp {
    pub fn apply_pending_plan(&mut self) {
        let Some(plan) = self.pending_plan.take() else {
            return;
        };
        let total = plan.changes.len();
        let mut applied = 0usize;
        for (idx, change) in plan.changes.into_iter().enumerate() {
            if self.plan_skipped.contains(&idx) {
                continue;
            }
            if self.apply_plan_change(change) {
                applied += 1;
            }
        }
        self.log("plan", format!("applied {applied}/{total} change(s)"));
        self.plan_cursor = 0;
        self.plan_skipped.clear();
        for line in plan.unsupported {
            self.log("plan-skip", line);
        }
    }

    fn apply_plan_change(&mut self, change: PlanChange) -> bool {
        match change {
            PlanChange::SetOption {
                global,
                tool,
                name,
                value,
            } => self.apply_set_option_plan_change(global, tool, name, value),
            PlanChange::Ask { question } => {
                self.handle_command(ShellCommand::Ask(question));
                true
            }
            PlanChange::Note { text } => {
                self.log("plan-note", text);
                true
            }
        }
    }

    fn apply_set_option_plan_change(
        &mut self,
        global: bool,
        tool: Option<String>,
        name: String,
        value: String,
    ) -> bool {
        if let Some(tool_name) = tool {
            self.handle_command(ShellCommand::Options {
                tool: Some(tool_name),
                filter: OptionsFilter::Standard,
            });
        }
        self.handle_command(ShellCommand::SetOption {
            global,
            name,
            value,
        });
        true
    }

    pub fn discard_pending_plan(&mut self) {
        if self.pending_plan.take().is_some() {
            self.plan_cursor = 0;
            self.plan_skipped.clear();
            self.log("plan", "discarded pending plan");
        }
    }
}
