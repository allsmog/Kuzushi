use super::*;

impl ShellApp {
    pub(in crate::app::batch_scan) fn cache_brief_result(&mut self, data: &Value) -> bool {
        let Some(target) = data["target"].as_str().map(std::path::PathBuf::from) else {
            return true;
        };
        let Some(editor) = self.runtime_state.brief_drafts.get_mut(&target) else {
            return true;
        };
        if !matches!(editor.mode, BriefMode::Loading | BriefMode::Saving) {
            return true;
        }
        let decoded = serde_json::from_value::<Option<BriefRevision>>(data["brief"].clone());
        let brief = match decoded {
            Ok(brief) => brief,
            Err(error) => {
                editor.mode = BriefMode::Read;
                editor.notice = Some(format!("Brief unavailable: {error}. Your draft is kept."));
                return true;
            }
        };
        let saved = editor.install(brief.clone());
        if saved {
            self.bind_saved_brief(&target, brief);
        }
        true
    }

    fn bind_saved_brief(&mut self, target: &std::path::Path, brief: Option<BriefRevision>) {
        let pending = self
            .runtime_state
            .brief_drafts
            .get(target)
            .and_then(|editor| editor.pending_study.clone());
        let Some(config) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .filter(|config| {
                config.target == target && Some(&config.study.investigation_id) == pending.as_ref()
            })
        else {
            return;
        };
        if config.brief_is_frozen() {
            self.runtime_state.brief_drafts.get_mut(target).unwrap().notice = Some("Revision saved. This frozen plan keeps its earlier brief; a new study can select the saved revision.".into());
            return;
        }
        config.study.brief = brief;
    }

    pub(crate) fn brief_save_failed(&mut self, tool: &str, error: &str) {
        if tool != "campaign:brief" {
            return;
        }
        for editor in self
            .runtime_state
            .brief_drafts
            .values_mut()
            .filter(|editor| matches!(editor.mode, BriefMode::Saving | BriefMode::Loading))
        {
            editor.mode = BriefMode::Review;
            editor.notice = Some(format!("Brief stopped: {error}. Your draft is kept. r reads the current base before another review."));
        }
    }
}

impl BriefEditor {
    fn install(&mut self, brief: Option<BriefRevision>) -> bool {
        let saved = self.mode == BriefMode::Saving && brief.is_some();
        if !self.preserve_text {
            self.editor = FieldEditor::new(
                brief
                    .as_ref()
                    .map_or("", |brief| brief.document.text.as_str()),
            );
        }
        self.mode = if brief.is_none() {
            BriefMode::Writing
        } else {
            BriefMode::Read
        };
        self.notice = Some(
            if brief.is_none() {
                "No saved brief. Enter a goal, priorities and questions; your draft is kept."
            } else {
                "Stored operator intent. No model calls, finding decisions or work approval."
            }
            .into(),
        );
        self.loaded = brief;
        self.preserve_text = false;
        saved
    }
}
