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
}
