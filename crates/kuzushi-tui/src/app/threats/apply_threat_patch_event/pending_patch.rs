use super::*;

impl ShellApp {
    pub(crate) fn reduce_threat_apply(&mut self) -> Vec<ShellEffect> {
        let Some(patch) = self.engagement.pending_threat_patch().cloned() else {
            self.log("threats", "No context changes are pending. Regenerated copies are inspected and selected in the context reader.");
            return Vec::new();
        };
        let Some(target) = self.target_owned() else {
            self.log(
                "error",
                "/threats apply requires an explicit target. Next: target <path> (or target .)",
            );
            return Vec::new();
        };
        vec![ShellEffect::ApplyThreatPatch(ThreatPatchApply {
            patch,
            target,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targetless_threat_patch_apply_is_refused_and_keeps_pending_patch() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_pending_threat_patch(ThreatPatch {
            goal: "add trust boundary".to_string(),
            summary: "add trust boundary".to_string(),
            patch: serde_json::json!({"dfd": {"trustBoundaries": []}}),
            unsupported: Vec::new(),
        });

        assert!(app.reduce_threat_apply().is_empty());
        assert!(app.engagement.pending_threat_patch().is_some());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires an explicit target")));
    }
}
