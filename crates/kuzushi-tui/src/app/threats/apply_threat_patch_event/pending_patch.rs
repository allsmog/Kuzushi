use super::*;

impl ShellApp {
    pub(crate) fn reduce_threat_apply(&mut self) -> Vec<ShellEffect> {
        let Some(patch) = self.pending_threat_patch.clone() else {
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
        if self.pending_threat_patch.take().is_some() {
            self.log("threats", "discarded pending patch");
        }
    }

    pub fn set_pending_threat_patch(&mut self, patch: ThreatPatch) {
        self.pending_threat_patch = Some(patch);
        self.threat_worker_running = false;
    }
}
