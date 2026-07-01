use super::*;

impl ShellApp {
    pub fn start_threat_regen(&mut self) {
        let Some(model) = self.prepare_threat_regen() else {
            return;
        };
        let cwd = threat_target_root(&self.target);
        let existing = persistent_threat_model_or_null(&cwd);
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let (tx, cancel) = self.start_threat_worker_channel("regenerating threat-model patch");

        thread::spawn(move || {
            threat_regen_worker(config, model, thinking_level, cwd, existing, tx, cancel)
        });
    }

    pub fn start_threat_ask(&mut self, question: &str) {
        let Some(question) = self.prepare_threat_question(question) else {
            return;
        };
        let Some(model) = self.require_valid_threat_model("/threats ask") else {
            return;
        };
        let cwd = threat_target_root(&self.target);
        let existing = persistent_threat_model_or_null(&cwd);
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let (tx, cancel) = self.start_threat_worker_channel(format!("asking: {question}"));

        thread::spawn(move || {
            threat_ask_worker(
                config,
                model,
                thinking_level,
                cwd,
                existing,
                question,
                tx,
                cancel,
            )
        });
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
        if self.pending_threat_patch.is_some() {
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
    ) -> (mpsc::Sender<ThreatPatchEvent>, ScanCancellation) {
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();
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
        (tx, cancel)
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
