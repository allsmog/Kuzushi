//! Operator-facing autonomy dial state on `ShellApp`.
//!
//! The live posture is transported to the shared dispatch gate through
//! `V2Config.autonomy` (an in-process, serde-skipped field), so the background
//! tool worker — which clones `self.config()` — carries the operator's current
//! rung automatically. These accessors keep that field the single source of
//! truth and clamp every change by the project-declared `phases.stop_after`
//! ceiling, so raising the dial can never authorize past an operator/project
//! cap.

use super::ShellApp;
use kuzushi_core::AutonomyPosture;

impl ShellApp {
    /// The live operator autonomy posture.
    pub(crate) fn autonomy(&self) -> AutonomyPosture {
        self.config().autonomy
    }

    /// The hard ceiling the dial may never exceed — the project-declared
    /// `phases.stop_after`, mapped onto a posture. Absent = no cap (`Fix`).
    pub(crate) fn autonomy_cap(&self) -> AutonomyPosture {
        self.config()
            .phases
            .stop_after
            .map(AutonomyPosture::from_guided_phase)
            .unwrap_or(AutonomyPosture::Fix)
    }

    /// Set the posture, clamped by the cap. Returns the applied value so the
    /// caller can report when the request was capped.
    pub(crate) fn set_autonomy(&mut self, posture: AutonomyPosture) -> AutonomyPosture {
        let applied = posture.capped_by(self.autonomy_cap());
        self.config_mut().autonomy = applied;
        applied
    }

    /// Ctrl+↑ — raise one rung (saturating, then capped).
    pub(crate) fn raise_autonomy(&mut self) {
        self.change_autonomy(self.autonomy().raised());
    }

    /// Ctrl+↓ — lower one rung (saturating).
    pub(crate) fn lower_autonomy(&mut self) {
        self.change_autonomy(self.autonomy().lowered());
    }

    /// Operator verb `autonomy [rung]` / `posture [rung]`. No rung reads the
    /// current posture; a rung sets it (clamped by the cap). Plain-mode parity
    /// comes for free — the transcript log renders in non-TTY output.
    pub(crate) fn reduce_autonomy_command(&mut self, requested: Option<AutonomyPosture>) {
        match requested {
            Some(posture) => self.change_autonomy(posture),
            None => self.report_autonomy_posture(),
        }
    }

    fn report_autonomy_posture(&mut self) {
        let posture = self.autonomy();
        self.log(
            "autonomy",
            format!(
                "posture {} (authorizes up to {}; cap {}) — Ctrl+Up/Down or `autonomy <recon|scan|review|prove|fix>`",
                posture.label(),
                posture.ceiling().word(),
                self.autonomy_cap().label(),
            ),
        );
    }

    fn change_autonomy(&mut self, requested: AutonomyPosture) {
        let previous = self.autonomy();
        let applied = self.set_autonomy(requested);
        if applied == previous {
            let message = format!(
                "posture stays at {} (cap: {})",
                applied.label(),
                self.autonomy_cap().label()
            );
            self.log("autonomy", &message);
            self.set_warn_notice("autonomy", message);
            return;
        }
        let message = format!(
            "posture → {} — authorizes up to the {} phase",
            applied.label(),
            applied.ceiling().word()
        );
        self.log("autonomy", &message);
        self.set_success_notice("autonomy", message);
    }
}

#[cfg(test)]
mod tests {
    use crate::app::ShellApp;
    use kuzushi_core::{AutonomyPosture, GuidedPhase, V2Config};

    #[test]
    fn default_posture_is_fix_behavior_preserving() {
        // The dial defaults to the most-permissive rung so existing dispatch
        // behavior is unchanged — the operator opts *into* constraint.
        let app = ShellApp::new(V2Config::default(), None);
        assert_eq!(app.autonomy(), AutonomyPosture::Fix);
    }

    #[test]
    fn raise_and_lower_saturate_within_bounds() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_autonomy(AutonomyPosture::ReconOnly);
        app.raise_autonomy();
        assert_eq!(app.autonomy(), AutonomyPosture::Scan);
        assert_eq!(
            app.advisory()
                .notice
                .as_ref()
                .map(|notice| notice.source.as_str()),
            Some("autonomy")
        );
        app.lower_autonomy();
        app.lower_autonomy();
        assert_eq!(app.autonomy(), AutonomyPosture::ReconOnly);
        app.lower_autonomy();
        assert_eq!(app.autonomy(), AutonomyPosture::ReconOnly);
    }

    #[test]
    fn stop_after_caps_the_dial() {
        let mut config = V2Config::default();
        config.phases.stop_after = Some(GuidedPhase::Scan);
        let mut app = ShellApp::new(config, None);
        // Requesting Fix is clamped to the project cap.
        let applied = app.set_autonomy(AutonomyPosture::Fix);
        assert_eq!(applied, AutonomyPosture::Scan);
        assert_eq!(app.autonomy(), AutonomyPosture::Scan);
        // Raising cannot exceed the cap either.
        app.raise_autonomy();
        assert_eq!(app.autonomy(), AutonomyPosture::Scan);
    }

    #[test]
    fn verb_sets_and_reads_without_panicking() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.reduce_autonomy_command(Some(AutonomyPosture::Prove));
        assert_eq!(app.autonomy(), AutonomyPosture::Prove);
        // Reading (None) leaves the posture unchanged.
        app.reduce_autonomy_command(None);
        assert_eq!(app.autonomy(), AutonomyPosture::Prove);
    }
}
