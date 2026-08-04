use super::*;

impl ShellApp {
    pub(crate) fn reduce_planner_start(&mut self, goal: &str) -> Vec<ShellEffect> {
        self.prepare_planner_start(goal)
            .map(|start| vec![ShellEffect::StartPlanner(start)])
            .unwrap_or_default()
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
                        "VIEW {} · REALITY {} — finish or explicitly skip the missing prerequisite before submitting {} work",
                        selected_phase.label(),
                        reality.label(),
                        selected_phase.label()
                    ),
                );
                return Vec::new();
            }
        }
        let goal = self.phase_intent_planner_goal(selected_phase, text);
        let Some(mut start) = self.prepare_planner_start(&goal) else {
            return Vec::new();
        };
        start.origin_phase = Some(selected_phase);
        start.phase_intent = Some(selected_phase);
        vec![ShellEffect::StartPlanner(start)]
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

    fn phase_intent_planner_goal(&self, phase: WorkflowPhase, text: &str) -> String {
        let tools = self
            .registry()
            .discoverable_tools()
            .filter(|tool| !tool.hidden)
            .filter(|tool| kuzushi_core::modules::autonomy::tool_phase(&tool.name) == Some(phase))
            .map(|tool| format!("{} — {}", tool.name, tool.description))
            .collect::<Vec<_>>();
        format!(
            "PHASE INTENT: {}\nOperator intent: {}\nAllowed descriptor tools (choose only from this list):\n{}\nReturn a run_tool change with canonical JSON input. If prerequisites or required values are missing, call request_user_input and continue this same planning turn. Never choose another phase, model, runtime, or tool outside this list.",
            phase.label(),
            text.trim(),
            tools.join("\n")
        )
    }

    pub(crate) fn dispatch_planner(&mut self, start: PlannerStart) {
        if self.reject_runtime_launch_while_budget_halted(true, "planner") {
            return;
        }
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Plan, "planner") else {
            return;
        };
        let generation = ticket.generation();
        let cancel = ticket.cancel.clone();
        let run_id = kuzushi_core::new_run_id("plan");
        self.begin_run_cost_tracking(&run_id, true);
        let session = ActivitySession::for_optional_phase(run_id.clone(), start.origin_phase);
        self.set_activity(Some(self.capture_run_focus_origin(session)));
        self.record_session_event(kuzushi_core::session_transcript::SessionEvent::RunStarted {
            run_id: run_id.clone(),
            tool_name: "planner:plan".to_string(),
        });
        self.set_plan_cancel(Some(cancel.clone()));
        self.set_planner_running(true);
        self.set_plan_abort_requested(false);
        self.log("plan", format!("planning: {}", start.goal));
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::CallingModel,
            "plan",
            "asking model for a structured proposal",
        ));

        let watchdog_cancel = cancel.clone();
        let loaded_modules = self.registry().loaded_module_specifiers();
        let metadata = ProposalRunMetadata {
            run_id,
            loaded_modules,
        };
        let handle = spawn_planner_job(start, metadata, ticket);
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
            phase_intent: None,
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

fn spawn_planner_job(
    start: PlannerStart,
    metadata: ProposalRunMetadata,
    ticket: JobTicket,
) -> std::thread::JoinHandle<()> {
    spawn_job_worker("planner", ticket, move |sink, cancel| {
        planner_worker(
            start.config,
            start.model,
            start.thinking_level,
            start.cwd,
            start.goal,
            start.phase_intent,
            metadata,
            sink,
            cancel,
        )
    })
}

pub(crate) struct PlannerStart {
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
    origin_phase: Option<WorkflowPhase>,
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
    fn planner_start_captures_only_an_explicit_guided_phase() {
        let mut app = planner_app();
        let manual = app
            .prepare_planner_start("inspect the target")
            .expect("manual planner start");
        assert_eq!(manual.origin_phase, None);

        app.engagement.set_phase(WorkflowPhase::Prove);
        let guided = app
            .prepare_planner_start("verify the selected finding")
            .expect("guided planner start");
        assert_eq!(guided.origin_phase, Some(WorkflowPhase::Prove));
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
