use crate::app::FieldEditor;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum AnswerFocus {
    #[default]
    Workspace,
    Reading,
    Reply,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AnswersRouteState {
    pub(crate) visible: bool,
    pub(crate) focus: AnswerFocus,
    pub(crate) draft: FieldEditor,
    pub(crate) scroll: Option<usize>,
    pub(crate) follow_response: bool,
    pub(crate) history: usize,
    drafts: BTreeMap<Option<PathBuf>, FieldEditor>,
}

impl AnswersRouteState {
    pub(crate) fn open(&mut self) {
        self.visible = true;
        self.focus = AnswerFocus::Reading;
    }

    pub(crate) fn close(&mut self) {
        self.visible = false;
        self.focus = AnswerFocus::Workspace;
    }

    pub(crate) fn reset_context(&mut self) {
        self.close();
        self.history = 0;
        self.scroll = None;
        self.follow_response = false;
    }

    pub(crate) fn switch_target(&mut self, prior: Option<PathBuf>, next: Option<PathBuf>) {
        let draft = std::mem::take(&mut self.draft);
        if !draft.text().is_empty() {
            self.drafts.insert(prior, draft);
        }
        self.draft = self.drafts.remove(&next).unwrap_or_default();
        self.reset_context();
    }

    pub(crate) fn submitted(&mut self, question: &str) {
        if self.draft.text().trim() == question.trim() {
            self.draft = Default::default();
        }
    }

    pub(crate) fn has_drafts(&self) -> bool {
        !self.draft.text().is_empty() || !self.drafts.is_empty()
    }

    pub(crate) fn restore_failed_question(
        &mut self,
        target: Option<PathBuf>,
        current_target: Option<PathBuf>,
        question: &str,
    ) {
        let draft = if target == current_target {
            &mut self.draft
        } else {
            self.drafts.entry(target).or_default()
        };
        if draft.text().is_empty() {
            draft.insert(question);
        }
    }

    pub(crate) fn begin_turn(&mut self) {
        self.visible = true;
        self.history = 0;
        self.scroll = None;
        self.follow_response = false;
        self.focus = AnswerFocus::Reading;
    }

    pub(crate) fn reply(&mut self) {
        self.history = 0;
        self.focus = AnswerFocus::Reply;
    }

    pub(crate) fn select_history(&mut self, delta: isize, count: usize) {
        self.history = self.history.saturating_add_signed(delta).min(count);
        self.scroll = None;
        self.follow_response = false;
    }
}
