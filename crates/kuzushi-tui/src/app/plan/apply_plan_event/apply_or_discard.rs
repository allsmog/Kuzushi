use super::*;

impl ShellApp {
    pub fn apply_pending_plan(&mut self) {
        let Some(plan) = self.take_pending_plan_for_apply() else {
            return;
        };
        self.apply_plan(plan);
    }

    fn take_pending_plan_for_apply(&mut self) -> Option<PlanProposal> {
        match self.engagement.take_pending_plan() {
            Some(plan) => Some(plan),
            None => {
                self.log("plan", "nothing to apply - no plan is pending");
                None
            }
        }
    }

    fn apply_plan(&mut self, plan: PlanProposal) {
        let total = plan.changes.len();
        let applied = self.apply_supported_plan_changes(plan.changes);
        self.log("plan", format!("applied {applied}/{total} change(s)"));
        self.reset_plan_review_state();
        self.log_unsupported_plan_changes(plan.unsupported);
    }

    fn apply_supported_plan_changes(&mut self, changes: Vec<PlanChange>) -> usize {
        let mut applied = 0usize;
        for (idx, change) in changes.into_iter().enumerate() {
            if self.engagement.plan_change_skipped(idx) {
                continue;
            }
            if self.apply_plan_change(change) {
                applied += 1;
            }
        }
        applied
    }

    fn reset_plan_review_state(&mut self) {
        self.engagement.reset_plan_review_state();
    }

    fn log_unsupported_plan_changes(&mut self, unsupported: Vec<String>) {
        for line in unsupported {
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
                update_and_execute_effects(self, Msg::Cmd(ShellCommand::Ask(question)));
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
            update_and_execute_effects(
                self,
                Msg::Cmd(ShellCommand::Options {
                    tool: Some(tool_name),
                    filter: OptionsFilter::Standard,
                }),
            );
        }
        update_and_execute_effects(
            self,
            Msg::Cmd(ShellCommand::SetOption {
                global,
                name,
                value,
            }),
        );
        true
    }

    pub fn discard_pending_plan(&mut self) {
        if self.engagement.discard_pending_plan() {
            self.log("plan", "discarded pending plan");
        } else {
            self.log("plan", "nothing to discard - no plan is pending");
        }
    }
}
