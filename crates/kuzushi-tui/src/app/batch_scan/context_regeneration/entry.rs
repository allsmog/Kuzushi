//! The public regeneration command enters immutable context selection.
use crate::app::{BatchScanConfig, ShellApp, StudyContextPicker};
use anyhow::{ensure, Context, Result};
use serde_json::json;

#[cfg(test)]
mod tests;

impl ShellApp {
    pub(crate) fn open_context_regeneration_entry(&mut self) -> Result<()> {
        ensure!(
            !self.has_running_work(),
            "Wait for active work before choosing context to regenerate. No new work started."
        );
        let target = self
            .target_owned()
            .context("threats regen requires an explicit target. Next: target <path>")?;
        ensure!(
            !self.engagement.has_pending_threat_patch(),
            "Review or reject the pending context changes first. They have been kept."
        );
        ensure!(self.router.campaign().batch_scan_config.is_none(), "Your study draft is still open. Use its Source and context row, or close it before opening separate regeneration. Your draft is kept.");
        let mut config = BatchScanConfig::load_for_map_study(&target);
        config.context_picker = Some(StudyContextPicker {
            regeneration_entry: true,
            scan_input: json!({"threatModelRef":null}),
            ..Default::default()
        });
        config.notice = Some("Choose a saved context revision and press Enter to read it. Then e selects text for regeneration. Model, guidance and allowance are reviewed before any request; the result is an inactive copy.".into());
        self.show_study_form(config);
        Ok(())
    }

    pub(in crate::app::batch_scan) fn handle_regeneration_context_selection_key(
        &mut self,
        code: crossterm::event::KeyCode,
    ) -> Option<crate::app::state_transitions::InputUpdate> {
        use crate::app::state_transitions::InputUpdate;
        if !self
            .study_context_picker()
            .is_some_and(|p| p.regeneration_entry)
        {
            return None;
        }
        if !crate::ui_view_models::study_context::action_available(self, code) {
            return Some(InputUpdate::handled());
        }
        if code == crossterm::event::KeyCode::Char('g') {
            self.open_context_editor();
            return Some(InputUpdate::handled());
        }
        None
    }
}
