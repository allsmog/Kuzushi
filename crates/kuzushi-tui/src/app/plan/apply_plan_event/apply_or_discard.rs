use super::*;

impl ShellApp {
    pub(crate) fn reduce_apply_pending_plan(&mut self) -> Vec<ShellEffect> {
        let Some(plan) = self.take_pending_plan_for_apply() else {
            return Vec::new();
        };
        self.reduce_apply_plan(plan)
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

    fn reduce_apply_plan(&mut self, plan: PlanProposal) -> Vec<ShellEffect> {
        let total = plan.changes.len();
        let (applied, effects) = self.reduce_supported_plan_changes(plan.changes);
        self.log("plan", format!("applied {applied}/{total} change(s)"));
        self.reset_plan_review_state();
        self.log_unsupported_plan_changes(plan.unsupported);
        effects
    }

    fn reduce_supported_plan_changes(
        &mut self,
        changes: Vec<PlanChange>,
    ) -> (usize, Vec<ShellEffect>) {
        let mut applied = 0usize;
        let mut effects = Vec::new();
        for (idx, change) in changes.into_iter().enumerate() {
            if self.engagement.plan_change_skipped(idx) {
                continue;
            }
            let (did_apply, mut change_effects) = self.reduce_plan_change(change);
            if did_apply {
                applied += 1;
            }
            effects.append(&mut change_effects);
        }
        (applied, effects)
    }

    fn reset_plan_review_state(&mut self) {
        self.engagement.reset_plan_review_state();
    }

    fn log_unsupported_plan_changes(&mut self, unsupported: Vec<String>) {
        for line in unsupported {
            self.log("plan-skip", line);
        }
    }

    fn reduce_plan_change(&mut self, change: PlanChange) -> (bool, Vec<ShellEffect>) {
        match change {
            PlanChange::SetOption {
                global,
                tool,
                name,
                value,
            } => self.reduce_set_option_plan_change(global, tool, name, value),
            PlanChange::Ask { question } => {
                let update = self.reduce_command_message(ShellCommand::Ask(question));
                (true, update.effects)
            }
            PlanChange::Note { text } => {
                self.log("plan-note", text);
                (true, Vec::new())
            }
        }
    }

    fn reduce_set_option_plan_change(
        &mut self,
        global: bool,
        tool: Option<String>,
        name: String,
        value: String,
    ) -> (bool, Vec<ShellEffect>) {
        let mut effects = Vec::new();
        if let Some(tool_name) = tool {
            let mut update = self.reduce_command_message(ShellCommand::Options {
                tool: Some(tool_name),
                filter: OptionsFilter::Standard,
            });
            effects.append(&mut update.effects);
        }
        let mut update = self.reduce_command_message(ShellCommand::SetOption {
            global,
            name,
            value,
        });
        effects.append(&mut update.effects);
        (true, effects)
    }

    pub(crate) fn reduce_discard_pending_plan(&mut self) -> Vec<ShellEffect> {
        if self.engagement.discard_pending_plan() {
            self.log("plan", "discarded pending plan");
        } else {
            self.log("plan", "nothing to discard - no plan is pending");
        }
        Vec::new()
    }
}
