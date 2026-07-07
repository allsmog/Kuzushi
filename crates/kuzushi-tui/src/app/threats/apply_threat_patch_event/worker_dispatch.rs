use super::*;

impl ShellApp {
    pub fn start_threat_regen(&mut self) {
        let effects = self.reduce_threat_regen();
        self.execute_effects(effects);
    }

    pub(crate) fn reduce_threat_regen(&mut self) -> Vec<ShellEffect> {
        self.prepare_threat_regen_start()
            .map(|start| vec![ShellEffect::StartThreat(start)])
            .unwrap_or_default()
    }

    pub(crate) fn dispatch_threat_worker(&mut self, start: ThreatWorkerStart) {
        let runtime = self.start_threat_worker_runtime(&start);
        let generation = runtime.generation;
        let watchdog_cancel = runtime.cancel.clone();
        let handle = spawn_threat_worker(start, runtime);
        self.register_worker_handle_with_watchdog(
            "threat model",
            generation,
            handle,
            watchdog_cancel,
        );
    }

    pub fn start_threat_ask(&mut self, question: &str) {
        let effects = self.reduce_threat_ask(question);
        self.execute_effects(effects);
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
        if self.threat_worker_running {
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
        if self.threat_worker_running {
            self.log("threats", "regen already running; wait first");
            return None;
        }
        Some(())
    }

    fn require_valid_threat_model(&mut self, command: &str) -> Option<String> {
        let Some(model) = self.config.model.clone() else {
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
            config: self.config.clone(),
            model,
            thinking_level: self.session_thinking_level.clone(),
            cwd: threat_target_root(&self.target),
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

    fn start_threat_worker_channel(
        &mut self,
        message: impl Into<String>,
    ) -> (
        mpsc::Sender<StampedEvent<ThreatPatchEvent>>,
        WorkerGeneration,
        ScanCancellation,
    ) {
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();
        let generation = self.next_worker_generation();
        self.threat_generation = Some(generation);
        self.threat_rx = Some(rx);
        self.threat_cancel = Some(cancel.clone());
        self.threat_worker_running = true;
        self.threat_abort_requested = false;
        let message = message.into();
        self.log("threats", message.clone());
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "threat model",
            message,
        ));
        (tx, generation, cancel)
    }

    fn start_threat_worker_runtime(&mut self, start: &ThreatWorkerStart) -> ThreatWorkerRuntime {
        let existing = persistent_threat_model_or_null(&start.cwd);
        let (tx, generation, cancel) = self.start_threat_worker_channel(start.message.clone());
        ThreatWorkerRuntime {
            tx,
            generation,
            cancel,
            existing,
            wake: self.loop_wake.clone(),
        }
    }
}

fn non_empty_threat_question(question: &str) -> Option<String> {
    let question = question.trim();
    (!question.is_empty()).then(|| question.to_string())
}

fn threat_target_root(target: &Option<PathBuf>) -> PathBuf {
    target
        .clone()
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
    tx: mpsc::Sender<StampedEvent<ThreatPatchEvent>>,
    generation: WorkerGeneration,
    cancel: ScanCancellation,
    existing: serde_json::Value,
    wake: Option<TerminalLoopWake>,
}

fn spawn_threat_worker(
    start: ThreatWorkerStart,
    runtime: ThreatWorkerRuntime,
) -> std::thread::JoinHandle<()> {
    match start.task.clone() {
        ThreatWorkerTask::Regenerate => spawn_threat_regen_worker(start, runtime),
        ThreatWorkerTask::Ask { question } => spawn_threat_ask_worker(start, runtime, question),
    }
}

fn spawn_threat_regen_worker(
    start: ThreatWorkerStart,
    runtime: ThreatWorkerRuntime,
) -> std::thread::JoinHandle<()> {
    let failure_tx = runtime.tx.clone();
    spawn_panic_safe_worker(
        "threat model",
        failure_tx,
        runtime.generation,
        runtime.wake.clone(),
        move || {
            threat_regen_worker(
                start.config,
                start.model,
                start.thinking_level,
                start.cwd,
                runtime.existing,
                runtime.tx,
                runtime.generation,
                runtime.cancel,
                runtime.wake,
            )
        },
        failed_threat_event,
    )
}

fn spawn_threat_ask_worker(
    start: ThreatWorkerStart,
    runtime: ThreatWorkerRuntime,
    question: String,
) -> std::thread::JoinHandle<()> {
    let failure_tx = runtime.tx.clone();
    spawn_panic_safe_worker(
        "threat model",
        failure_tx,
        runtime.generation,
        runtime.wake.clone(),
        move || {
            threat_ask_worker(
                start.config,
                start.model,
                start.thinking_level,
                start.cwd,
                runtime.existing,
                question,
                runtime.tx,
                runtime.generation,
                runtime.cancel,
                runtime.wake,
            )
        },
        failed_threat_event,
    )
}

fn failed_threat_event(error: String) -> ThreatPatchEvent {
    ThreatPatchEvent::Failed { error }
}
