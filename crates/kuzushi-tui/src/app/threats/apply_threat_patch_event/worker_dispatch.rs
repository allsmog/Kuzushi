use super::*;

impl ShellApp {
    pub(crate) fn reduce_threat_regen(&mut self) -> Vec<ShellEffect> {
        self.prepare_threat_regen_start()
            .map(|start| vec![ShellEffect::StartThreat(start)])
            .unwrap_or_default()
    }

    pub(crate) fn dispatch_threat_worker(&mut self, start: ThreatWorkerStart) {
        let ticket = self.jobs_mut().start(JobKind::Threat, "threat model");
        let generation = ticket.generation();
        let watchdog_cancel = ticket.cancel.clone();
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
        let model = self.prepare_threat_regen()?;
        Some(self.threat_worker_start(
            model,
            "regenerating threat-model patch",
            ThreatWorkerTask::Regenerate,
        ))
    }

    fn prepare_threat_ask_start(&mut self, question: &str) -> Option<ThreatWorkerStart> {
        let question = self.prepare_threat_question(question)?;
        let model = self.require_valid_threat_model("/threats ask")?;
        let message = format!("asking: {question}");
        Some(self.threat_worker_start(model, message, ThreatWorkerTask::Ask { question }))
    }

    fn threat_worker_start(
        &self,
        model: String,
        message: impl Into<String>,
        task: ThreatWorkerTask,
    ) -> ThreatWorkerStart {
        ThreatWorkerStart {
            config: self.config().clone(),
            model,
            thinking_level: self.session_thinking_level_owned(),
            cwd: threat_target_root(self.target()),
            message: message.into(),
            task,
        }
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

fn threat_target_root(target: Option<&std::path::Path>) -> PathBuf {
    target
        .map(std::path::Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
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
