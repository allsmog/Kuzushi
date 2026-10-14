use crate::app::{state_transitions::InputUpdate, FieldEditor, ShellApp};
use kuzushi_core::capabilities::campaign::BriefRevision;
use serde_json::{json, Value};

mod completion;
mod keys;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BriefMode {
    Loading,
    Read,
    Writing,
    Review,
    Saving,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BriefEditor {
    pub mode: BriefMode,
    pub loaded: Option<BriefRevision>,
    pub editor: FieldEditor,
    pub scroll: usize,
    pub preserve_text: bool,
    pub pending_study: Option<String>,
    pub notice: Option<String>,
}

impl Default for BriefEditor {
    fn default() -> Self {
        Self {
            mode: BriefMode::Loading,
            loaded: None,
            editor: FieldEditor::default(),
            scroll: 0,
            preserve_text: false,
            pending_study: None,
            notice: None,
        }
    }
}

impl ShellApp {
    pub(crate) fn brief_editor(&self) -> Option<&BriefEditor> {
        let config = self.router.campaign().batch_scan_config.as_ref()?;
        if !config.brief_open {
            return None;
        }
        self.runtime_state.brief_drafts.get(&config.target)
    }

    pub(super) fn brief_editor_mut(&mut self) -> Option<&mut BriefEditor> {
        let target = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .target
            .clone();
        self.runtime_state.brief_drafts.get_mut(&target)
    }

    pub(super) fn open_investigation_brief(&mut self) -> InputUpdate {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return InputUpdate::handled();
        };
        config.brief_open = true;
        let target = config.target.clone();
        if self.runtime_state.brief_drafts.contains_key(&target) {
            return InputUpdate::handled();
        }
        let selected = config
            .study
            .brief
            .as_ref()
            .map(|brief| brief.reference.clone());
        self.runtime_state
            .brief_drafts
            .insert(target, BriefEditor::default());
        let mut input = json!({"mode":"read"});
        if let Some(reference) = selected {
            input["briefRef"] = json!(reference);
        }
        self.dispatch_brief(input)
    }

    pub(super) fn dispatch_brief(&mut self, input: Value) -> InputUpdate {
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some("campaign:brief".into()), Some(input.to_string())),
        )
    }

    pub(super) fn close_brief(&mut self) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.brief_open = false;
        }
    }

    pub(super) fn use_loaded_brief(&mut self) {
        let Some(selected) = self.brief_editor().and_then(|editor| editor.loaded.clone()) else {
            self.brief_editor_mut().unwrap().notice =
                Some("Review and save this text before selecting a brief.".into());
            return;
        };
        if self.brief_editor().unwrap().editor.text() != selected.document.text {
            self.brief_editor_mut().unwrap().notice = Some("Unsaved text differs from this revision. Ctrl+S reviews a new revision before selection.".into());
            return;
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if config.brief_is_frozen() {
            config.notice = Some(
                "This plan keeps its frozen brief. Start a new study to select another revision."
                    .into(),
            );
            return;
        }
        config.study.brief = Some(selected);
        config.brief_open = false;
        config.detail_scroll = 0;
    }
}
