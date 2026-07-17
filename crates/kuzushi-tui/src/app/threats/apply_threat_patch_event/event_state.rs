use super::*;

impl ShellApp {
    pub(crate) fn apply_threat_patch_event(&mut self, event: ThreatPatchEvent) {
        self.set_threat_worker_running(false);
        self.settle_active_run_cost_report(threat_event_audit(&event).settlement_cost());
        if self.threat_abort_requested() {
            self.set_threat_abort_requested(false);
            self.log(
                "threats",
                "LangGraph response arrived after abort request; discarded",
            );
            self.set_refused_activity("threat model", "response discarded after abort request");
            return;
        }
        match event {
            ThreatPatchEvent::Proposed { patch, .. } => {
                self.log(
                    "threats",
                    format!(
                        "patch proposed; {} unsupported note(s); review with /threats apply or /threats reject",
                        patch.unsupported.len()
                    ),
                );
                self.engagement.set_pending_threat_patch(patch);
                self.set_completed_activity("threat model", "patch ready for review");
            }
            ThreatPatchEvent::Answer { text, .. } => {
                self.log("threats", text);
                self.set_completed_activity("threat model", "answer received");
            }
            ThreatPatchEvent::Failed { error, .. } => {
                let safe_error = kuzushi_core::runtime::safe_model_failure_message(&error);
                self.log("error", format!("threats worker failed: {safe_error}"));
                self.set_refused_activity("threat model", "worker failed");
            }
        }
    }
}

fn threat_event_audit(event: &ThreatPatchEvent) -> &AgentCallAudit {
    match event {
        ThreatPatchEvent::Proposed { audit, .. }
        | ThreatPatchEvent::Answer { audit, .. }
        | ThreatPatchEvent::Failed { audit, .. } => audit,
    }
}
