use super::*;

impl ShellApp {
    pub(crate) fn apply_plan_event(&mut self, event: PlanEvent) {
        self.planner_running = false;
        if self.discard_aborted_plan_event() {
            return;
        }
        self.apply_finished_plan_event(event);
    }

    fn discard_aborted_plan_event(&mut self) -> bool {
        if !self.plan_abort_requested {
            return false;
        }
        self.plan_abort_requested = false;
        self.log(
            "plan",
            "LangGraph response arrived after abort request; discarded",
        );
        self.set_paused_activity("plan", "proposal discarded after abort request");
        true
    }

    fn apply_finished_plan_event(&mut self, event: PlanEvent) {
        match event {
            PlanEvent::Proposed(plan) => {
                self.log(
                    "plan",
                    format!(
                        "{} change(s); press [y] to apply, [n] to discard",
                        plan.changes.len()
                    ),
                );
                self.plan_cursor = 0;
                self.plan_skipped.clear();
                self.pending_plan = Some(plan);
                self.set_completed_activity("plan", "proposal ready for review");
            }
            PlanEvent::Failed { error } => {
                self.log("error", format!("planner failed: {error}"));
                self.set_refused_activity("plan", "planner failed");
            }
        }
    }

    pub fn set_pending_plan(&mut self, plan: PlanProposal) {
        self.planner_running = false;
        self.plan_cursor = 0;
        self.plan_skipped.clear();
        self.pending_plan = Some(plan);
    }
}
