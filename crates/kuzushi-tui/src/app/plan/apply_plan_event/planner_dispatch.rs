use super::*;

impl ShellApp {
    pub(crate) fn reduce_planner_start(&mut self, goal: &str) -> Vec<ShellEffect> {
        self.prepare_planner_start(goal)
            .map(|start| vec![ShellEffect::StartPlanner(start)])
            .unwrap_or_default()
    }

    pub(crate) fn dispatch_planner(&mut self, start: PlannerStart) {
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Plan, "planner") else {
            return;
        };
        let generation = ticket.generation();
        let cancel = ticket.cancel.clone();
        self.set_activity(Some(ActivitySession::for_optional_phase(
            kuzushi_core::new_run_id("plan"),
            start.origin_phase,
        )));
        self.set_plan_cancel(Some(cancel.clone()));
        self.set_planner_running(true);
        self.set_plan_abort_requested(false);
        self.log("plan", format!("planning: {}", start.goal));
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "plan",
            "asking model for a structured proposal",
        ));

        let watchdog_cancel = cancel.clone();
        let handle = spawn_job_worker("planner", ticket, move |sink, cancel| {
            planner_worker(
                start.config,
                start.model,
                start.thinking_level,
                start.cwd,
                start.goal,
                sink,
                cancel,
            )
        });
        self.register_worker_handle_with_watchdog("planner", generation, handle, watchdog_cancel);
    }

    fn prepare_planner_start(&mut self, goal: &str) -> Option<PlannerStart> {
        let goal = self.accept_planner_goal(goal)?;
        let model = self.planner_model()?;
        let cwd = self.planner_target()?;
        Some(PlannerStart {
            config: self.config().clone(),
            model,
            thinking_level: self.session_thinking_level_owned(),
            cwd,
            goal,
            origin_phase: self.engagement.current_phase(),
        })
    }

    fn accept_planner_goal(&mut self, goal: &str) -> Option<String> {
        let goal = goal.trim();
        if goal.is_empty() {
            self.log(
                "error",
                "/plan requires a goal. Next: /plan focus on SSRF in admin routes",
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
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
    origin_phase: Option<WorkflowPhase>,
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
    fn planner_start_captures_only_an_explicit_guided_phase() {
        let mut app = planner_app();
        let manual = app
            .prepare_planner_start("inspect the target")
            .expect("manual planner start");
        assert_eq!(manual.origin_phase, None);

        app.engagement.set_phase(WorkflowPhase::Confirm);
        let guided = app
            .prepare_planner_start("verify the selected finding")
            .expect("guided planner start");
        assert_eq!(guided.origin_phase, Some(WorkflowPhase::Confirm));
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
