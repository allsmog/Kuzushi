use super::*;

impl ShellApp {
    pub fn start_planner(&mut self, goal: &str) {
        let goal = goal.trim();
        if goal.is_empty() {
            self.log(
                "error",
                "/plan requires a goal. Next: /plan focus on SSRF in admin routes",
            );
            return;
        }
        if self.planner_running {
            self.log("plan", "planner already running; wait for the proposal");
            return;
        }
        if self.pending_plan.is_some() {
            self.log("plan", "discard the current pending plan first with /no");
            return;
        }

        let Some(model) = self.config.model.clone() else {
            self.log(
                "error",
                "/plan requires an explicit model. Next: model, then choose a pi-agent-core provider/model",
            );
            return;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }

        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let goal_owned = goal.to_string();
        let (tx, rx) = mpsc::channel();
        self.plan_rx = Some(rx);
        self.planner_running = true;
        self.plan_abort_requested = false;
        self.log("plan", format!("planning: {goal_owned}"));

        thread::spawn(move || planner_worker(config, model, thinking_level, cwd, goal_owned, tx));
    }
}
