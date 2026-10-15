//! One captured source, an explicit human verdict, and a durable receipt.
use super::*;
mod keys;
mod state;
mod worker;
pub(crate) use state::{SourceReviewForm, SourceReviewMode, SourceReviewWorker, SOURCE_VERDICTS};

impl ShellApp {
    pub(crate) fn source_review_form(&self) -> Option<&SourceReviewForm> {
        let key = self.runtime_state.source_review_visible.as_ref()?;
        if self.target() != Some(key.0.as_path()) {
            return None;
        }
        self.runtime_state.source_review_forms.get(key)
    }

    pub(super) fn source_review_form_mut(&mut self) -> Option<&mut SourceReviewForm> {
        let key = self.runtime_state.source_review_visible.as_ref()?;
        self.runtime_state.source_review_forms.get_mut(key)
    }

    pub(crate) fn open_current_source_review(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let Some((_, finding)) = crate::ui_view_models::visible_finding_at_cursor(self) else {
            return;
        };
        let Some(id) = finding.id else {
            return;
        };
        let key = (target.clone(), id);
        let form = SourceReviewForm {
            target,
            finding_id: id,
            title: finding.title.clone(),
            file: finding.file_path.clone(),
            line: finding.start_line,
            mode: SourceReviewMode::Intro,
            capture: None,
            verdict: 0,
            reason: Default::default(),
            scroll: 0,
            reading_scroll: 0,
            show_source_receipt: false,
            notice: None,
            decision_id: None,
        };
        self.runtime_state
            .source_review_forms
            .entry(key.clone())
            .or_insert(form);
        self.runtime_state.source_review_visible = Some(key);
    }

    pub(super) fn close_source_review(&mut self) {
        if let Some(worker) = self.runtime_state.source_review_worker.as_ref() {
            worker.cancel.cancel();
        }
        self.runtime_state.source_review_visible = None;
    }

    pub(crate) fn insert_source_review_paste(&mut self, text: &str) -> bool {
        let Some(form) = self.source_review_form_mut() else {
            return false;
        };
        if form.mode == SourceReviewMode::Reason {
            form.reason.insert(text);
            form.notice = None;
        }
        true
    }
}

#[cfg(test)]
mod tests;
