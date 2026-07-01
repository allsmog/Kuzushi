use super::*;

impl ShellApp {
    pub fn start_planner(&mut self, goal: &str) {
        let Some(start) = self.prepare_planner_start(goal) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();
        self.plan_rx = Some(rx);
        self.plan_cancel = Some(cancel.clone());
        self.planner_running = true;
        self.plan_abort_requested = false;
        self.log("plan", format!("planning: {}", start.goal));
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "plan",
            "asking model for a structured proposal",
        ));

        thread::spawn(move || {
            planner_worker(
                start.config,
                start.model,
                start.thinking_level,
                start.cwd,
                start.goal,
                tx,
                cancel,
            )
        });
    }

    fn prepare_planner_start(&mut self, goal: &str) -> Option<PlannerStart> {
        let goal = self.accept_planner_goal(goal)?;
        let model = self.planner_model()?;
        Some(PlannerStart {
            config: self.config.clone(),
            model,
            thinking_level: self.session_thinking_level.clone(),
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
        if self.planner_running {
            self.log("plan", "planner already running; wait for the proposal");
            return None;
        }
        if self.pending_plan.is_some() {
            self.log("plan", "discard the current pending plan first with /no");
            return None;
        }
        Some(())
    }

    fn planner_model(&mut self) -> Option<String> {
        let Some(model) = self.config.model.clone() else {
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
        self.target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

struct PlannerStart {
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
}
