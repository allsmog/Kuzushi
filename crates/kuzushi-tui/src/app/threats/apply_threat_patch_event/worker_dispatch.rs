use super::*;

impl ShellApp {
    pub(crate) fn reduce_threat_regen(&mut self) -> Vec<ShellEffect> {
        self.prepare_threat_regen_start()
            .map(|start| vec![ShellEffect::StartThreat(start)])
            .unwrap_or_default()
    }

    pub(crate) fn dispatch_threat_worker(&mut self, start: ThreatWorkerStart) {
        if self.reject_runtime_launch_while_budget_halted(true, "threat model") {
            return;
        }
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Threat, "threat model") else {
            return;
        };
        let generation = ticket.generation();
        let watchdog_cancel = ticket.cancel.clone();
        let run_id = kuzushi_core::new_run_id("threat");
        self.begin_run_cost_tracking(&run_id, true);
        self.set_activity(Some(ActivitySession::for_optional_phase(
            run_id,
            start.origin_phase,
        )));
        let runtime = self.start_threat_worker_runtime(&start, watchdog_cancel.clone());
        let handle = spawn_threat_worker(start, runtime, ticket);
        self.register_worker_handle_with_watchdog(
            "threat model",
            generation,
            handle,
            watchdog_cancel,
        );
    }

    pub(crate) fn reduce_threat_ask(&mut self, question: &str) -> Vec<ShellEffect> {
        self.prepare_threat_ask_start(question)
            .map(|start| vec![ShellEffect::StartThreat(start)])
            .unwrap_or_default()
    }

    fn prepare_threat_regen(&mut self) -> Option<String> {
        self.reject_threat_regen_blockers()?;
        self.require_valid_threat_model("/threats regen")
    }

    fn reject_threat_regen_blockers(&mut self) -> Option<()> {
        if self.threat_worker_running() {
            self.log("threats", "regen already running; wait for the proposal");
            return None;
        }
        if self.engagement.has_pending_threat_patch() {
            self.log(
                "threats",
                "discard the pending patch first with /threats reject",
            );
            return None;
        }
        Some(())
    }

    fn prepare_threat_question(&mut self, question: &str) -> Option<String> {
        self.reject_threat_ask_blockers()?;
        non_empty_threat_question(question).or_else(|| {
            self.log(
                "error",
                "/threats ask requires a question. Next: /threats ask what attack surface is in admin?",
            );
            None
        })
    }

    fn reject_threat_ask_blockers(&mut self) -> Option<()> {
        if self.threat_worker_running() {
            self.log("threats", "regen already running; wait first");
            return None;
        }
        Some(())
    }

    fn require_valid_threat_model(&mut self, command: &str) -> Option<String> {
        let Some(model) = self.config().model.clone() else {
            self.log(
                "error",
                format!("{command} requires an explicit model. Next: model"),
            );
            return None;
        };
        self.checked_threat_model(model)
    }

    fn prepare_threat_regen_start(&mut self) -> Option<ThreatWorkerStart> {
        let cwd = self.require_threat_target("/threats regen")?;
        let model = self.prepare_threat_regen()?;
        Some(self.threat_worker_start(
            model,
            "regenerating threat-model patch",
            ThreatWorkerTask::Regenerate,
            cwd,
        ))
    }

    fn prepare_threat_ask_start(&mut self, question: &str) -> Option<ThreatWorkerStart> {
        let cwd = self.require_threat_target("/threats ask")?;
        let question = self.prepare_threat_question(question)?;
        let model = self.require_valid_threat_model("/threats ask")?;
        let message = format!("asking: {question}");
        Some(self.threat_worker_start(model, message, ThreatWorkerTask::Ask { question }, cwd))
    }

    fn threat_worker_start(
        &self,
        model: String,
        message: impl Into<String>,
        task: ThreatWorkerTask,
        cwd: PathBuf,
    ) -> ThreatWorkerStart {
        ThreatWorkerStart {
            config: self.config().clone(),
            model,
            thinking_level: self.session_thinking_level_owned(),
            cwd,
            message: message.into(),
            task,
            origin_phase: self.engagement.current_phase(),
        }
    }

    fn require_threat_target(&mut self, command: &str) -> Option<PathBuf> {
        self.target_owned().or_else(|| {
            self.log(
                "error",
                format!("{command} requires an explicit target. Next: target <path> (or target .)"),
            );
            None
        })
    }

    fn checked_threat_model(&mut self, model: String) -> Option<String> {
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return None;
        }
        Some(model)
    }

    fn begin_threat_worker_state(&mut self, message: impl Into<String>, cancel: ScanCancellation) {
        self.set_threat_cancel(Some(cancel.clone()));
        self.set_threat_worker_running(true);
        self.set_threat_abort_requested(false);
        let message = message.into();
        self.log("threats", message.clone());
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "threat model",
            message,
        ));
    }

    fn start_threat_worker_runtime(
        &mut self,
        start: &ThreatWorkerStart,
        cancel: ScanCancellation,
    ) -> ThreatWorkerRuntime {
        let existing = persistent_threat_model_or_null(&start.cwd);
        self.begin_threat_worker_state(start.message.clone(), cancel);
        ThreatWorkerRuntime { existing }
    }
}

fn non_empty_threat_question(question: &str) -> Option<String> {
    let question = question.trim();
    (!question.is_empty()).then(|| question.to_string())
}

fn persistent_threat_model_or_null(cwd: &PathBuf) -> serde_json::Value {
    load_persistent_threat_model(cwd).unwrap_or(serde_json::Value::Null)
}

pub(crate) struct ThreatWorkerStart {
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    message: String,
    task: ThreatWorkerTask,
    origin_phase: Option<WorkflowPhase>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_start_captures_only_an_explicit_guided_phase() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let target = PathBuf::from("/explicit-threat-target");
        app.set_target(Some(target.clone()));
        let manual = app.threat_worker_start(
            "openai:gpt-test".to_string(),
            "inspect threats",
            ThreatWorkerTask::Regenerate,
            target.clone(),
        );
        assert_eq!(manual.origin_phase, None);

        app.engagement.set_phase(WorkflowPhase::Map);
        let guided = app.threat_worker_start(
            "openai:gpt-test".to_string(),
            "build the threat model",
            ThreatWorkerTask::Regenerate,
            target,
        );
        assert_eq!(guided.origin_phase, Some(WorkflowPhase::Map));
    }

    #[test]
    fn targetless_threat_worker_is_refused() {
        let mut app = ShellApp::new(
            V2Config {
                model: Some("openai:gpt-test".to_string()),
                ..V2Config::default()
            },
            None,
        );

        assert!(app.reduce_threat_regen().is_empty());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires an explicit target")));
    }
}

#[derive(Clone)]
enum ThreatWorkerTask {
    Regenerate,
    Ask { question: String },
}

struct ThreatWorkerRuntime {
    existing: serde_json::Value,
}

fn spawn_threat_worker(
    start: ThreatWorkerStart,
    runtime: ThreatWorkerRuntime,
    ticket: JobTicket,
) -> std::thread::JoinHandle<()> {
    let ThreatWorkerStart {
        config,
        model,
        thinking_level,
        cwd,
        message: _,
        task,
        origin_phase: _,
    } = start;
    let existing = runtime.existing;
    spawn_job_worker("threat model", ticket, move |sink, cancel| match task {
        ThreatWorkerTask::Regenerate => {
            threat_regen_worker(config, model, thinking_level, cwd, existing, sink, cancel)
        }
        ThreatWorkerTask::Ask { question } => threat_ask_worker(
            config,
            model,
            thinking_level,
            cwd,
            existing,
            question,
            sink,
            cancel,
        ),
    })
}
