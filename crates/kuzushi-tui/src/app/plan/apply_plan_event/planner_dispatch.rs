use super::*;

impl ShellApp {
    pub(crate) fn reduce_planner_start(&mut self, goal: &str) -> Vec<ShellEffect> {
        if goal.trim().is_empty() && self.resume_workflow_proposal() {
            return Vec::new();
        }
        let Some(start) = self.prepare_planner_start(goal) else {
            return Vec::new();
        };
        self.prepare_bounded_workflow_proposal(&start.goal, None);
        Vec::new()
    }

    pub(crate) fn reduce_phase_intent(
        &mut self,
        selected_phase: WorkflowPhase,
        text: &str,
    ) -> Vec<ShellEffect> {
        if self.phase_intent_has_unresolved_attempt(selected_phase) {
            self.log(
                "phase",
                format!(
                    "{} has an unresolved result. Select or discard that attempt before submitting another bare intent; navigation and explicit commands remain available.",
                    selected_phase.label()
                ),
            );
            return Vec::new();
        }
        if let Some(reality) = crate::ui_view_models::journey_model(self).map(|model| model.current)
        {
            if selected_phase > reality {
                self.log(
                    "phase",
                    format!(
                        "VIEW {} · REALITY {} · finish or explicitly skip the missing prerequisite before submitting {} work",
                        selected_phase.label(),
                        reality.label(),
                        selected_phase.label()
                    ),
                );
                return Vec::new();
            }
        }
        let Some(start) = self.prepare_planner_start(text) else {
            return Vec::new();
        };
        self.prepare_bounded_workflow_proposal(&start.goal, Some(selected_phase));
        Vec::new()
    }

    fn prepare_bounded_workflow_proposal(&mut self, goal: &str, phase: Option<WorkflowPhase>) {
        if let Err(error) = self.plan_workflow_proposal(goal, phase) {
            self.set_error_notice("plan", format!("Planning needs a reviewed job: {error:#}"));
        }
    }

    fn phase_intent_has_unresolved_attempt(&mut self, phase: WorkflowPhase) -> bool {
        let Some(target) = self.target_owned() else {
            return false;
        };
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(&target);
        match kuzushi_core::workflow_attempts::load_phase_attempt_ledger(&target) {
            Ok(ledger) => ledger.unresolved_for(phase, &snapshot).is_some(),
            Err(error) => {
                self.log(
                    "workflow",
                    format!("phase intent blocked because attempt state is unreadable: {error}"),
                );
                true
            }
        }
    }

    pub(crate) fn dispatch_planner(&mut self, start: PlannerStart) {
        self.prepare_bounded_workflow_proposal(&start.goal, start.phase_intent);
    }

    fn prepare_planner_start(&mut self, goal: &str) -> Option<PlannerStart> {
        let goal = self.accept_planner_goal(goal)?;
        self.planner_model()?;
        self.planner_target()?;
        Some(PlannerStart {
            goal,
            phase_intent: None,
        })
    }

    fn accept_planner_goal(&mut self, goal: &str) -> Option<String> {
        let goal = goal.trim();
        if goal.is_empty() {
            self.log(
                "error",
                "/plan requires a goal when no draft is kept. Next: /plan prioritize repository context",
            );
            return None;
        }
        self.reject_planner_busy_states()?;
        Some(goal.to_string())
    }

    fn reject_planner_busy_states(&mut self) -> Option<()> {
        if self.planner_running() {
            self.log("plan", "planner already running; wait for the proposal");
            return None;
        }
        if self.engagement.has_pending_plan() {
            self.log("plan", "discard the current pending plan first with /no");
            return None;
        }
        Some(())
    }

    fn planner_model(&mut self) -> Option<String> {
        let Some(model) = self.config().model.clone() else {
            self.log(
                "error",
                "/plan requires an explicit model. Next: model, then choose a LangGraph provider/model",
            );
            return None;
        };
        match validate_shell_model_id(&model) {
            Ok(()) => Some(model),
            Err(message) => {
                self.log("error", message);
                None
            }
        }
    }

    fn planner_target(&mut self) -> Option<PathBuf> {
        self.target_owned().or_else(|| {
            self.log(
                "error",
                "/plan requires an explicit target. Next: target <path> (or target .)",
            );
            None
        })
    }
}

pub(crate) struct PlannerStart {
    goal: String,
    phase_intent: Option<WorkflowPhase>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planner_app() -> ShellApp {
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-test".to_string()),
                ..V2Config::default()
            },
            None,
        );
        app.set_target(Some(PathBuf::from("/explicit-planner-target")));
        app
    }

    #[test]
    fn free_form_planner_never_implicitly_inherits_the_visible_phase() {
        let mut app = planner_app();
        let manual = app
            .prepare_planner_start("inspect the target")
            .expect("manual planner start");
        assert_eq!(manual.phase_intent, None);

        app.engagement.set_phase(WorkflowPhase::Review);
        let guided = app
            .prepare_planner_start("inspect the selected finding")
            .expect("guided planner start");
        assert_eq!(guided.phase_intent, None);
    }

    #[test]
    fn targetless_planner_is_refused_without_starting_work() {
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-test".to_string()),
                ..V2Config::default()
            },
            None,
        );

        assert!(app.reduce_planner_start("inspect the target").is_empty());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires an explicit target")));
    }
}
