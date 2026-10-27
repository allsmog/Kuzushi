use super::*;
use serde_json::json;

impl ShellApp {
    pub(crate) fn open_lesson_source_file_picker(&mut self) {
        if self.has_running_work() {
            return;
        }
        let Some(generation) = self
            .context_generation()
            .filter(|g| g.is_lesson() && g.receipt.is_none())
        else {
            return;
        };
        let paths = generation.context_input["sourceEvidenceFiles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect();
        self.open_file_picker_for(FilePickerPurpose::LessonEvidence);
        *self.router.file_picker_mut().review_selection_mut() =
            ReviewFileSelection::with_paths(paths);
    }

    pub(super) fn apply_lesson_source_files(&mut self) {
        let paths = self
            .router
            .file_picker()
            .review_selection()
            .paths()
            .to_vec();
        self.go_back();
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(generation) = config
            .context_generation
            .as_mut()
            .filter(|g| g.is_lesson() && g.receipt.is_none())
        else {
            return;
        };
        let same = generation
            .context_input
            .get("sourceEvidenceFiles")
            .map_or(paths.is_empty(), |value| value == &json!(paths));
        if same {
            return;
        }
        generation.context_input["sourceEvidenceFiles"] = json!(paths);
        generation
            .context_input
            .as_object_mut()
            .unwrap()
            .remove("sourceEvidenceRef");
        generation.clear_model_plan();
        config.study.invalidate_plan();
        config.notice = Some("Supporting paths changed. Preparation reads only their recorded snapshot bytes under one shared limit. Missing historical captures are disclosed. No model request started.".into());
    }
}
