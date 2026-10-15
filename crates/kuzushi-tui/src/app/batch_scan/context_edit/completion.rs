use super::*;
use kuzushi_core::ThreatModelRef;

impl ShellApp {
    pub(in crate::app::batch_scan) fn cache_context_edit_result(&mut self, data: &Value) -> bool {
        match edited_copy_receipt(data) {
            Ok((target, source, copy)) => self.install_edited_context_copy(target, source, copy),
            Err(error) => self.context_edit_save_failed("threat-model:revise", &error.to_string()),
        }
        true
    }

    fn install_edited_context_copy(
        &mut self,
        target: PathBuf,
        source: ThreatModelRef,
        copy: ThreatModelRef,
    ) {
        let key = (target.clone(), source.revision_id.as_str().into());
        let Some(draft) = self.runtime_state.context_edit_drafts.get(&key) else {
            return;
        };
        if draft.reference != source || draft.mode != ContextEditMode::Saving {
            return;
        }
        self.resolve_context_checkpoint(&key);
        self.runtime_state.context_edit_drafts.remove(&key);
        if self.target() != Some(target.as_path()) {
            return;
        }
        if self.install_copy_in_context_picker(&source, &copy) {
            self.set_batch_config_notice("Edited copy saved. Enter inspects it; a selects it for this study. The active model is unchanged.");
        } else {
            self.set_batch_config_notice(format!("Edited copy saved as {}. Find it in the context catalog. Your selection is unchanged.",copy.revision_id));
        }
    }

    fn install_copy_in_context_picker(
        &mut self,
        source: &ThreatModelRef,
        copy: &ThreatModelRef,
    ) -> bool {
        let matching = self.study_context_picker().is_some_and(|picker| {
            picker.selected.as_ref() == Some(source) && picker.editor_visible
        });
        if !matching {
            return false;
        }
        self.edit_context_picker(|config| {
            let Some(picker) = config.context_picker.as_mut() else {
                return;
            };
            if picker.selected.as_ref() != Some(source) || !picker.editor_visible {
                return;
            }
            picker.selected = Some(copy.clone());
            picker.editor_visible = false;
            picker.preview = None;
            picker.diagram = None;
            picker.diagram_visible = false;
            picker.map_attempt_id = None;
            picker.detail_scroll = 0;
            picker.text_view = crate::app::StudyContextTextView::Summary;
        });
        true
    }

    pub(crate) fn context_edit_save_failed(&mut self, tool: &str, error: &str) {
        if tool != "threat-model:revise" {
            return;
        }
        for draft in self.runtime_state.context_edit_drafts.values_mut() {
            if draft.mode == ContextEditMode::Saving {
                draft.mode = ContextEditMode::Review;
                draft.notice = Some(format!("Save stopped: {error}. Your draft is kept. Inspect the context catalog before retrying."));
            }
        }
    }
}

fn edited_copy_receipt(data: &Value) -> anyhow::Result<(PathBuf, ThreatModelRef, ThreatModelRef)> {
    anyhow::ensure!(
        data["activated"] == false,
        "Edited copy receipt did not confirm inactive state"
    );
    let target = data["target"]
        .as_str()
        .context("Edited copy target is missing")?;
    let source = serde_json::from_value(data["sourceModelRef"].clone())
        .context("Edited copy base reference is missing")?;
    let copy = serde_json::from_value(data["modelRef"].clone())
        .context("Edited copy reference is missing")?;
    Ok((target.into(), source, copy))
}
