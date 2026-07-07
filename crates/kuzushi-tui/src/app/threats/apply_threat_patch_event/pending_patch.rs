use super::*;

impl ShellApp {
    pub(crate) fn reduce_threat_apply(&mut self) -> Vec<ShellEffect> {
        let Some(patch) = self.engagement.pending_threat_patch().cloned() else {
            self.log("threats", "no pending patch; run /threats regen first");
            return Vec::new();
        };
        vec![ShellEffect::ApplyThreatPatch(ThreatPatchApply {
            patch,
            target: self.target_owned(),
        })]
    }

    pub fn discard_pending_threat_patch(&mut self) {
        if self.engagement.take_pending_threat_patch().is_some() {
            self.log("threats", "discarded pending patch");
            self.set_refused_activity("threat model", "pending patch rejected");
        }
    }

    pub fn set_pending_threat_patch(&mut self, patch: ThreatPatch) {
        self.engagement.set_pending_threat_patch(patch);
        self.set_threat_worker_running(false);
    }
}
