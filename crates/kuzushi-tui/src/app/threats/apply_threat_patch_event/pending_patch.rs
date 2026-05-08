use super::*;

impl ShellApp {
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
