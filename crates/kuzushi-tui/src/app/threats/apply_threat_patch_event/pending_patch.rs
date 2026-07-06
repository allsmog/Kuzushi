use super::*;

impl ShellApp {
    pub(crate) fn reduce_threat_apply(&mut self) -> Vec<ShellEffect> {
        let Some(patch) = self.engagement.pending_threat_patch().cloned() else {
            self.log("threats", "no pending patch; run /threats regen first");
            return Vec::new();
        };
        vec![ShellEffect::ApplyThreatPatch(ThreatPatchApply {
            patch,
            target: self.target.clone(),
        })]
    }

    pub fn apply_pending_threat_patch(&mut self) {
        let effects = self.reduce_threat_apply();
        self.execute_effects(effects);
    }

    pub fn discard_pending_threat_patch(&mut self) {
        if self.engagement.take_pending_threat_patch().is_some() {
            self.log("threats", "discarded pending patch");
        }
    }

    pub fn set_pending_threat_patch(&mut self, patch: ThreatPatch) {
        self.engagement.set_pending_threat_patch(patch);
        self.threat_worker_running = false;
    }
}
