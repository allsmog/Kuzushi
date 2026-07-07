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
use crate::ui_view_models::journey_model;
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

    /// Align the dial to where the engagement actually is (reality-derived
    /// journey phase), never above the cap. A fresh, target-less or
    /// artifact-less workspace lands on `ReconOnly` — a project can never
    /// *ship* a posture that auto-authorizes patching. Called once at startup;
    /// posture is otherwise operator-driven and never silently elevated.
    pub(crate) fn initialize_default_autonomy(&mut self) {
        let derived = journey_model(self).map(|journey| journey.current);
        let base = derived
            .map(AutonomyPosture::from_phase)
            .unwrap_or(AutonomyPosture::ReconOnly);
        self.set_autonomy(base);
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
                "posture {} {} (authorizes up to {}; cap {}) — Ctrl+Up/Down or `autonomy <recon|hunt|confirm|fix>`",
                posture.kanji(),
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
            self.log(
                "autonomy",
                format!(
                    "posture stays at {} {} (cap: {})",
                    applied.kanji(),
                    applied.label(),
                    self.autonomy_cap().label()
                ),
            );
            return;
        }
        self.log(
            "autonomy",
            format!(
                "posture → {} {} — authorizes up to the {} phase",
                applied.kanji(),
                applied.label(),
                applied.ceiling().word()
            ),
        );
    }
}
