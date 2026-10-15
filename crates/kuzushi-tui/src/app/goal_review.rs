//! A read/review overlay preserves the underlying Review composer and origin.
use super::*;
use kuzushi_core::findings::{FindingGoalPage, FindingGoalRow, GoalRelevance};
use std::path::PathBuf;
mod keys;
mod worker;

pub(crate) const GOAL_FILTERS: [&str; 6] = [
    "all",
    "unassessed",
    "direct",
    "related",
    "outside",
    "uncertain",
];

#[derive(Debug, Default)]
pub(crate) struct GoalReviewState {
    pub(crate) target: Option<PathBuf>,
    pub(crate) visible: bool,
    pub(crate) origin: Option<ShellView>,
    pub(crate) discarding: bool,
    pub(crate) brief_id: String,
    pub(crate) page: Option<Result<FindingGoalPage, String>>,
    pub(crate) cursor: usize,
    pub(crate) pinned: Option<i64>,
    pub(crate) offset: usize,
    pub(crate) filter: usize,
    pub(crate) scroll: usize,
    pub(crate) show_brief: bool,
    pub(crate) show_keys: bool,
    pub(crate) show_history: bool,
    pub(crate) history_id: Option<i64>,
    pub(crate) history: Option<Result<Vec<kuzushi_core::findings::FindingGoalAssessment>, String>>,
    pub(crate) show_receipt: bool,
    pub(crate) form: Option<GoalAssessmentForm>,
    pub(crate) editing: bool,
    pub(crate) notice: Option<String>,
    pub(crate) pending_receipt: Option<String>,
}

#[derive(Debug)]
pub(crate) struct GoalAssessmentForm {
    pub(crate) brief: kuzushi_core::capabilities::campaign::BriefRevision,
    pub(crate) row: FindingGoalRow,
    pub(crate) relevance: GoalRelevance,
    pub(crate) reason: FieldEditor,
    pub(crate) confirming: bool,
}

pub(crate) struct GoalReviewWorker {
    pub(crate) target: PathBuf,
    pub(crate) writing: bool,
    pub(crate) history_id: Option<i64>,
    pub(crate) handle: std::thread::JoinHandle<Result<serde_json::Value, String>>,
}

impl std::fmt::Debug for GoalReviewWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoalReviewWorker")
            .field("target", &self.target)
            .field("writing", &self.writing)
            .finish()
    }
}

impl GoalReviewState {
    fn resume_draft(
        &mut self,
        brief: &kuzushi_core::capabilities::campaign::BriefRevision,
        row: &FindingGoalRow,
        relevance: GoalRelevance,
    ) -> bool {
        let Some(form) = &mut self.form else {
            return false;
        };
        if form.row.basis == row.basis && &form.brief == brief {
            form.relevance = relevance;
            form.row = row.clone();
            form.confirming = false;
            self.editing = true;
        } else {
            self.notice = Some("A draft for another finding or brief is retained. d resumes it; x reviews discarding it.".into());
        }
        true
    }

    pub(crate) fn selected(&self) -> Option<&FindingGoalRow> {
        let page = self.page.as_ref()?.as_ref().ok()?;
        if let Some(id) = self.pinned {
            return page.rows.iter().find(|row| row.basis.finding_id == id);
        }
        page.rows.get(self.cursor)
    }
}

impl ShellApp {
    pub(crate) fn goal_review(&self) -> Option<&GoalReviewState> {
        let state = &self.runtime_state.goal_review;
        if state.origin != Some(self.shell_view()) || self.budget_halt_owns_input() {
            return None;
        }
        (state.visible && state.target.as_deref() == self.target()).then_some(state)
    }

    pub(crate) fn has_goal_assessment_drafts(&self) -> bool {
        std::iter::once(&self.runtime_state.goal_review)
            .chain(self.runtime_state.goal_review_states.values())
            .any(|state| state.form.is_some())
    }

    pub(crate) fn open_goal_review(&mut self, brief_id: Option<&str>) {
        let Some(target) = self.target_owned() else {
            self.set_warn_notice("goals", "Select a target before reviewing goal relevance.");
            return;
        };
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let id = brief_id.unwrap_or("repository");
        self.select_goal_state(target, id);
        let origin = self.shell_view();
        let state = &mut self.runtime_state.goal_review;
        state.origin = Some(origin);
        state.visible = true;
        if state.page.is_none() {
            self.read_goal_review(false);
        }
    }

    fn select_goal_state(&mut self, target: PathBuf, id: &str) {
        let state = &self.runtime_state.goal_review;
        if state.target.as_ref() == Some(&target) && state.brief_id == id {
            return;
        }
        let previous = std::mem::take(&mut self.runtime_state.goal_review);
        if let Some(old_target) = previous.target.clone() {
            self.runtime_state
                .goal_review_states
                .insert((old_target, previous.brief_id.clone()), previous);
        }
        self.runtime_state.goal_review = self
            .runtime_state
            .goal_review_states
            .remove(&(target.clone(), id.into()))
            .unwrap_or_else(|| GoalReviewState {
                target: Some(target),
                brief_id: id.into(),
                ..Default::default()
            });
    }

    pub(crate) fn paste_goal_reason(&mut self, text: &str) -> bool {
        if self.goal_review().is_none() {
            return false;
        }
        if self.runtime_state.goal_review_worker.is_some() {
            return true;
        }
        if let Some(editor) = self.goal_reason_editor() {
            editor.insert(text);
        }
        true
    }

    fn goal_reason_editor(&mut self) -> Option<&mut FieldEditor> {
        let state = &mut self.runtime_state.goal_review;
        if !state.editing || state.discarding || state.show_keys {
            return None;
        }
        state
            .form
            .as_mut()
            .filter(|form| !form.confirming)
            .map(|form| &mut form.reason)
    }

    pub(super) fn begin_goal_assessment(&mut self, relevance: GoalRelevance) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let state = &mut self.runtime_state.goal_review;
        let Some(Ok(page)) = &state.page else {
            return;
        };
        let Some(brief) = page.brief.clone() else {
            return;
        };
        let Some(row) = state.selected().cloned() else {
            return;
        };
        if state.resume_draft(&brief, &row, relevance) {
            return;
        }
        let reason = row
            .assessment
            .as_ref()
            .map(|record| record.reason.clone())
            .unwrap_or_default();
        state.form = Some(GoalAssessmentForm {
            brief,
            row,
            relevance,
            reason: FieldEditor::new(reason),
            confirming: false,
        });
        state.editing = true;
        state.scroll = 0;
        state.notice = None;
    }
}

#[cfg(test)]
mod tests;
