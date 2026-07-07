use super::*;

impl ShellApp {
    pub(crate) fn reduce_planner_start(&mut self, goal: &str) -> Vec<ShellEffect> {
        self.prepare_planner_start(goal)
            .map(|start| vec![ShellEffect::StartPlanner(start)])
            .unwrap_or_default()
    }

    pub(crate) fn dispatch_planner(&mut self, start: PlannerStart) {
        let ticket = self.jobs.start(JobKind::Plan, "planner");
        let generation = ticket.generation();
        let cancel = ticket.cancel.clone();
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
        Some(PlannerStart {
            config: self.config().clone(),
            model,
            thinking_level: self.session_thinking_level_owned(),
            cwd: self.planner_cwd(),
            goal,
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

    fn planner_cwd(&self) -> PathBuf {
        self.target_owned()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

pub(crate) struct PlannerStart {
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
}
