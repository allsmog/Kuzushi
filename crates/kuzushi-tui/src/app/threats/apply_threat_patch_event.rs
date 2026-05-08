use super::*;

impl ShellApp {
    pub(crate) fn apply_threat_patch_event(&mut self, event: ThreatPatchEvent) {
        self.threat_worker_running = false;
        if self.threat_abort_requested {
            self.threat_abort_requested = false;
            self.log(
                "threats",
                "pi-agent-core response arrived after abort request; discarded",
            );
            return;
        }
        match event {
            ThreatPatchEvent::Proposed(patch) => {
                self.log(
                    "threats",
                    format!(
                        "patch proposed; {} unsupported note(s); review with /threats apply or /threats reject",
                        patch.unsupported.len()
                    ),
                );
                self.pending_threat_patch = Some(patch);
            }
            ThreatPatchEvent::Answer { text } => {
                self.log("threats", text);
            }
            ThreatPatchEvent::Failed { error } => {
                self.log("error", format!("threats worker failed: {error}"));
            }
        }
    }

    pub fn start_threat_regen(&mut self) {
        if self.threat_worker_running {
            self.log("threats", "regen already running; wait for the proposal");
            return;
        }
        if self.pending_threat_patch.is_some() {
            self.log(
                "threats",
                "discard the pending patch first with /threats reject",
            );
            return;
        }
        let Some(model) = self.config.model.clone() else {
            self.log(
                "error",
                "/threats regen requires an explicit model. Next: model",
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
        let existing = load_persistent_threat_model(&cwd).unwrap_or(serde_json::Value::Null);
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let (tx, rx) = mpsc::channel();
        self.threat_rx = Some(rx);
        self.threat_worker_running = true;
        self.threat_abort_requested = false;
        self.log("threats", "regenerating threat-model patch");

        thread::spawn(move || {
            threat_regen_worker(config, model, thinking_level, cwd, existing, tx)
        });
    }

    pub fn start_threat_ask(&mut self, question: &str) {
        if self.threat_worker_running {
            self.log("threats", "regen already running; wait first");
            return;
        }
        let question = question.trim();
        if question.is_empty() {
            self.log(
                "error",
                "/threats ask requires a question. Next: /threats ask what attack surface is in admin?",
            );
            return;
        }
        let Some(model) = self.config.model.clone() else {
            self.log(
                "error",
                "/threats ask requires an explicit model. Next: model",
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
        let existing = load_persistent_threat_model(&cwd).unwrap_or(serde_json::Value::Null);
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let question = question.to_string();
        let (tx, rx) = mpsc::channel();
        self.threat_rx = Some(rx);
        self.threat_worker_running = true;
        self.threat_abort_requested = false;
        self.log("threats", format!("asking: {question}"));

        thread::spawn(move || {
            threat_ask_worker(config, model, thinking_level, cwd, existing, question, tx)
        });
    }

    pub fn apply_pending_threat_patch(&mut self) {
        let Some(patch) = self.pending_threat_patch.take() else {
            self.log("threats", "no pending patch; run /threats regen first");
            return;
        };
        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let mut document =
            load_persistent_threat_model(&cwd).unwrap_or_else(|| serde_json::json!({}));
        merge_json(&mut document, &patch.patch);
        match save_persistent_threat_model(&cwd, &document, true) {
            Ok(_) => {
                self.log(
                    "threats",
                    format!(
                        "applied patch ({} unsupported note(s))",
                        patch.unsupported.len()
                    ),
                );
                for note in patch.unsupported {
                    self.log("threats-skip", note);
                }
            }
            Err(error) => self.log("error", format!("failed to write threat model: {error}")),
        }
    }

    pub fn discard_pending_threat_patch(&mut self) {
        if self.pending_threat_patch.take().is_some() {
            self.log("threats", "discarded pending patch");
        }
    }

    pub fn set_pending_threat_patch(&mut self, patch: ThreatPatch) {
        self.pending_threat_patch = Some(patch);
        self.threat_worker_running = false;
    }
}
