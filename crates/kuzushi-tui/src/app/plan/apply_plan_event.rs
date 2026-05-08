use super::*;

impl ShellApp {
    pub(crate) fn apply_plan_event(&mut self, event: PlanEvent) {
        self.planner_running = false;
        if self.plan_abort_requested {
            self.plan_abort_requested = false;
            self.log(
                "plan",
                "pi-agent-core response arrived after abort request; discarded",
            );
            return;
        }
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
            }
            PlanEvent::Failed { error } => {
                self.log("error", format!("planner failed: {error}"));
            }
        }
    }

    pub fn set_pending_plan(&mut self, plan: PlanProposal) {
        self.planner_running = false;
        self.plan_cursor = 0;
        self.plan_skipped.clear();
        self.pending_plan = Some(plan);
    }

    pub fn plan_change_count(&self) -> usize {
        self.pending_plan
            .as_ref()
            .map(|plan| plan.changes.len())
            .unwrap_or(0)
    }

    pub fn plan_cursor_clamped(&self) -> usize {
        let total = self.plan_change_count();
        if total == 0 {
            0
        } else {
            self.plan_cursor.min(total - 1)
        }
    }

    pub fn plan_change_skipped(&self, idx: usize) -> bool {
        self.plan_skipped.contains(&idx)
    }

    pub fn move_plan_cursor(&mut self, delta: i32) {
        let total = self.plan_change_count();
        if total == 0 {
            self.plan_cursor = 0;
            return;
        }
        let cur = self.plan_cursor.min(total - 1) as i32;
        self.plan_cursor = (cur + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub fn toggle_plan_change_skip(&mut self) {
        if self.plan_change_count() == 0 {
            return;
        }
        let idx = self.plan_cursor_clamped();
        if self.plan_skipped.contains(&idx) {
            self.plan_skipped.remove(&idx);
        } else {
            self.plan_skipped.insert(idx);
        }
    }

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
            match change {
                PlanChange::SetOption {
                    global,
                    tool,
                    name,
                    value,
                } => {
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
                    applied += 1;
                }
                PlanChange::Ask { question } => {
                    self.handle_command(ShellCommand::Ask(question));
                    applied += 1;
                }
                PlanChange::Note { text } => {
                    self.log("plan-note", text);
                    applied += 1;
                }
            }
        }
        self.log("plan", format!("applied {applied}/{total} change(s)"));
        self.plan_cursor = 0;
        self.plan_skipped.clear();
        for line in plan.unsupported {
            self.log("plan-skip", line);
        }
    }

    pub fn discard_pending_plan(&mut self) {
        if self.pending_plan.take().is_some() {
            self.plan_cursor = 0;
            self.plan_skipped.clear();
            self.log("plan", "discarded pending plan");
        }
    }
}
