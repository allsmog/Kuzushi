//! Manual edits retain their exact base and never activate or select a copy implicitly.
use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::Context;
use serde_json::{json, Value};
use std::path::PathBuf;
mod completion;
mod keys;
mod state;
#[cfg(test)]
mod tests;
pub(crate) use state::{ContextDraftRecovery, ContextEditDraft, ContextEditEntry, ContextEditMode};

impl ShellApp {
    pub(in crate::app::batch_scan) fn context_edit_selection_key(
        &self,
    ) -> Option<(PathBuf, String)> {
        let reference = self.study_context_picker()?.selected.as_ref()?;
        Some((self.target_owned()?, reference.revision_id.as_str().into()))
    }

    pub(crate) fn context_edit_draft(&self) -> Option<&ContextEditDraft> {
        if !self.study_context_picker()?.editor_visible {
            return None;
        }
        self.runtime_state
            .context_edit_drafts
            .get(&self.context_edit_selection_key()?)
    }

    pub(super) fn context_edit_draft_mut(&mut self) -> Option<&mut ContextEditDraft> {
        let key = self.context_edit_selection_key()?;
        self.runtime_state.context_edit_drafts.get_mut(&key)
    }

    pub(super) fn open_context_editor(&mut self) {
        if self.restore_context_editor() {
            return;
        }
        match self.context_editor_input() {
            Ok((key, reference, preview, label)) => {
                self.runtime_state
                    .context_edit_drafts
                    .entry(key.clone())
                    .or_insert_with(|| ContextEditDraft::new(reference, &preview.document, label));
                self.edit_context_picker(|config| {
                    config.context_picker.as_mut().unwrap().editor_visible = true
                });
                self.start_context_draft_recovery(&key);
            }
            Err(error) => self.set_batch_config_notice(format!("{error:#}")),
        }
    }

    fn restore_context_editor(&mut self) -> bool {
        let Some(key) = self.context_edit_selection_key() else {
            return false;
        };
        let Some(draft) = self.runtime_state.context_edit_drafts.get(&key) else {
            return false;
        };
        if self
            .study_context_picker()
            .and_then(|picker| picker.selected.as_ref())
            != Some(&draft.reference)
        {
            return false;
        }
        self.edit_context_picker(|config| {
            config.context_picker.as_mut().unwrap().editor_visible = true
        });
        true
    }

    fn context_editor_input(
        &self,
    ) -> anyhow::Result<(
        (PathBuf, String),
        kuzushi_core::ThreatModelRef,
        std::sync::Arc<super::study_context::StudyContextPreview>,
        String,
    )> {
        let picker = self
            .study_context_picker()
            .context("Open study context first.")?;
        let reference = picker
            .selected
            .clone()
            .context("Choose a context revision before editing.")?;
        let preview = picker
            .preview
            .clone()
            .context("Inspect this exact revision with Enter before editing.")?;
        let key = self
            .context_edit_selection_key()
            .context("Select a target first.")?;
        let catalog = crate::ui_view_models::study_context::context_catalog(self);
        let label = catalog
            .rows
            .iter()
            .find(|row| row.reference.as_ref() == Some(&reference))
            .and_then(|row| row.copy_label.clone())
            .unwrap_or_else(|| "Edited context".into());
        Ok((key, reference, preview, label))
    }

    fn close_context_editor(&mut self) {
        self.edit_context_picker(|config| {
            config.context_picker.as_mut().unwrap().editor_visible = false
        });
    }

    fn review_context_edits(&mut self) {
        let Some(draft) = self.context_edit_draft_mut() else {
            return;
        };
        match draft.validate() {
            Ok(_) => {
                draft.mode = ContextEditMode::Review;
                draft.scroll = 0;
                draft.notice = None;
            }
            Err(error) => draft.notice = Some(error.to_string()),
        }
    }

    fn save_context_edits(&mut self) -> InputUpdate {
        if self.has_running_work() {
            self.context_edit_draft_mut().unwrap().notice =
                Some("Wait for active work. Your edits are kept.".into());
            return InputUpdate::handled();
        }
        let draft = self.context_edit_draft_mut().unwrap();
        let edits = match draft.validate() {
            Ok(edits) => edits,
            Err(error) => {
                draft.notice = Some(error.to_string());
                return InputUpdate::handled();
            }
        };
        let input =
            json!({"threatModelRef":draft.reference,"edits":edits,"label":draft.entries[0].text()});
        draft.mode = ContextEditMode::Saving;
        draft.notice = Some("Saving a separate context copy. No model calls.".into());
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some("threat-model:revise".into()), Some(input.to_string())),
        )
    }
}
