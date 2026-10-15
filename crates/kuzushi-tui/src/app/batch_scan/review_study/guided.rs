use super::*;
use crate::app::{onboarding::planning_task_explicit_input, PlanningTaskId};

impl ShellApp {
    /// Selecting triage requests a finite draft before authentication or work.
    pub(crate) fn review_selected_triage_plan(
        &mut self,
        plan: &[PlanningTaskId],
    ) -> Option<InputUpdate> {
        if !plan.contains(&PlanningTaskId::TriageFindings) {
            return None;
        }
        if self.has_running_work() {
            self.set_warn_notice(
                "planning",
                "Wait for active work before planning Review. Your selection is retained.",
            );
            return Some(InputUpdate::handled());
        }
        Some(match self.selected_review_step() {
            Ok(step) => self.open_selected_review_plan(plan, step),
            Err(error) => {
                self.set_warn_notice(
                    "planning",
                    format!("Review options need attention: {error:#}. No work started."),
                );
                InputUpdate::handled()
            }
        })
    }

    fn selected_review_step(&self) -> Result<PlanningRunStep> {
        let task = PlanningTaskId::TriageFindings;
        let mut input = self.resolved_input_for_planning_task(task)?;
        if !self.review_worker_was_selected() {
            input["concurrency"] = json!(1);
        }
        Ok(PlanningRunStep {
            task,
            tool_name: task.tool_name().into(),
            input,
        })
    }

    fn review_worker_was_selected(&self) -> bool {
        let explicit = planning_task_explicit_input(
            PlanningTaskId::TriageFindings,
            self.engagement.option_overrides(),
        );
        explicit.get("concurrency").is_some()
            || self
                .option_store()
                .effective_stored_value_scope("triage:run", "concurrency")
                .is_some()
    }

    fn open_selected_review_plan(
        &mut self,
        plan: &[PlanningTaskId],
        step: PlanningRunStep,
    ) -> InputUpdate {
        self.engagement.queue_plan(
            plan.iter()
                .copied()
                .filter(|task| *task != PlanningTaskId::TriageFindings)
                .collect(),
        );
        if let Err(error) = self.plan_review_step(step) {
            self.engagement.pause_planning_queue();
            self.set_warn_notice("planning",format!("Review plan unavailable: {error:#}. Selection remains paused; no work started."));
        }
        InputUpdate::handled()
    }
}
