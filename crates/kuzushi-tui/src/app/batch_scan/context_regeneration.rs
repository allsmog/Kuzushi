use super::context_generation::StudyContextGeneration;
use crate::app::ShellApp;
use anyhow::Context;
use serde_json::{json, Value};
mod entry;
mod guidance;
#[cfg(test)]
mod tests;

impl ShellApp {
    pub(in crate::app::batch_scan) fn plan_selected_text_regeneration(&mut self) {
        if self.has_running_work() {
            self.context_regeneration_notice(
                "Wait for active work before planning text regeneration.",
            );
            return;
        }
        match self.selected_regeneration_input() {
            Ok((input, label)) => self.open_selected_text_generation(input, label),
            Err(error) => self.context_regeneration_notice(&format!("{error:#}")),
        }
    }

    fn selected_regeneration_input(&self) -> anyhow::Result<(Value, String)> {
        let draft = self
            .context_edit_draft()
            .context("Inspect context and select a text field first")?;
        anyhow::ensure!(!draft.entries.iter().any(|entry|entry.changed()),"Save or explicitly discard your edits before regenerating from this exact revision. Your draft is kept.");
        let entry = &draft.entries[draft.cursor];
        anyhow::ensure!(entry.regeneratable, "This architecture field is edited locally. Select overview, description, purpose or an answer for text regeneration.");
        let pointer = entry
            .pointer
            .as_ref()
            .context("Select a context text field; copy names are not regenerated")?;
        Ok((
            json!({"threatModelRef":draft.reference,"fields":[pointer]}),
            entry.label.clone(),
        ))
    }

    fn open_selected_text_generation(&mut self, input: Value, label: String) {
        self.edit_context_picker(|config| {
            if let Some(picker)=config.context_picker.as_mut() { picker.editor_visible=false; }
            config.context_generation=Some(StudyContextGeneration {generation_tool:Some("threat-model:regenerate".into()),context_input:input,return_context_editor:true,selected_text_label:Some(label.clone()),..Default::default()});
            config.notice=Some(format!("Selected text: {label}. Plan one synthesis request as a separate inactive draft. Unselected text and the original remain intact; review changes before use. No model request has started."));
        });
    }

    pub(in crate::app::batch_scan) fn restore_regeneration_editor(&mut self) -> bool {
        if !self
            .context_generation()
            .is_some_and(|generation| generation.return_context_editor)
        {
            return false;
        }
        self.edit_context_picker(|config| {
            config.context_generation = None;
            if let Some(picker) = config.context_picker.as_mut() {
                picker.editor_visible = true;
            }
            config.notice = None;
        });
        true
    }

    fn context_regeneration_notice(&mut self, text: &str) {
        if let Some(draft) = self.context_edit_draft_mut() {
            draft.notice = Some(text.into());
        }
    }
}
