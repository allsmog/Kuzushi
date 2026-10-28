use super::*;
use kuzushi_core::capabilities::campaign::MAX_REVIEW_SUPPORTING_FILES;
use serde_json::{json, Value};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReviewFileSelection {
    paths: Vec<String>,
    basket: bool,
    alternate_query: FieldEditor,
    alternate_cursor: usize,
    notice: Option<String>,
}

impl ReviewFileSelection {
    pub(crate) fn with_paths(paths: Vec<String>) -> Self {
        Self {
            paths,
            ..Self::default()
        }
    }
    pub(crate) fn paths(&self) -> &[String] {
        &self.paths
    }
    pub(crate) fn basket(&self) -> bool {
        self.basket
    }
    pub(crate) fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub(crate) fn candidates(&self, indexed: &[String]) -> Vec<String> {
        if self.basket {
            return self.paths.clone();
        }
        indexed.iter().chain(&self.paths).cloned().collect()
    }

    pub(crate) fn switch_view(&mut self, query: &mut FieldEditor, cursor: &mut usize) {
        std::mem::swap(query, &mut self.alternate_query);
        std::mem::swap(cursor, &mut self.alternate_cursor);
        self.basket = !self.basket;
    }

    pub(crate) fn toggle(&mut self, path: String) {
        self.notice = None;
        if let Some(index) = self.paths.iter().position(|selected| selected == &path) {
            self.paths.remove(index);
            return;
        }
        if self.paths.len() >= MAX_REVIEW_SUPPORTING_FILES {
            self.notice = Some(format!("Select at most {MAX_REVIEW_SUPPORTING_FILES} files. Remove a choice before adding another."));
            return;
        }
        self.paths.push(path);
    }
}

impl ShellApp {
    pub(crate) fn open_review_source_file_picker(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(review) = config.review_plan.as_ref() else {
            return;
        };
        if review.input["strategy"] != "standard" || review.input["sourceEvidence"] != "cited" {
            config.notice = Some("Use s to select standard Review and e to select cited source before choosing supporting files. No input or spending changed.".into());
            return;
        }
        let paths = review.input["sourceEvidenceFiles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        self.open_file_picker_for(FilePickerPurpose::ReviewEvidence);
        *self.router.file_picker_mut().review_selection_mut() =
            ReviewFileSelection::with_paths(paths);
    }

    pub(super) fn handle_review_file_picker_key(&mut self, key: KeyEvent) -> bool {
        if !self.router.file_picker().purpose().is_source_evidence() {
            return false;
        }
        match key.code {
            KeyCode::Char(' ') => {
                self.toggle_review_file_choice();
                true
            }
            KeyCode::Tab => {
                self.router.file_picker_mut().toggle_review_basket();
                true
            }
            _ => false,
        }
    }

    fn toggle_review_file_choice(&mut self) {
        let route = self.router.file_picker_mut();
        let path = route
            .selected_path()
            .or_else(|| (!route.query().trim().is_empty()).then(|| route.query().to_string()));
        if let Some(path) = path {
            route.review_selection_mut().toggle(path);
        }
        route.move_cursor(0);
    }

    pub(super) fn apply_review_source_files(&mut self) {
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
        let Some(review) = config.review_plan.as_mut() else {
            return;
        };
        let same = review
            .input
            .get("sourceEvidenceFiles")
            .map_or(paths.is_empty(), |value| value == &json!(paths));
        if same {
            return;
        }
        let Some(input) = review.input.as_object_mut() else {
            return;
        };
        input.insert("sourceEvidenceFiles".into(), json!(paths));
        input.remove("sourceEvidenceRef");
        review.scroll = 0;
        review.show_evidence = false;
        review.show_options = false;
        config.study.invalidate_plan();
        config.notice = Some("Supporting files changed explicitly. Enter freezes their text and omissions under the shared byte limit. Review the new bundle before approval; no job or request started.".into());
    }
}
