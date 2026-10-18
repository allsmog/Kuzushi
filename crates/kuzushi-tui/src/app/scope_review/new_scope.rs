//! Explicit discovery membership additions, without work or model generation.
use super::*;
use kuzushi_core::workspace::{ProposedScanScope, ScanScopeEdit};

impl ShellApp {
    pub(super) fn open_new_discovery_scope(&mut self) {
        let Some(state) = self.router.scope_review_mut().as_mut() else {
            return;
        };
        let Some(review) = state.review.as_ref() else {
            return;
        };
        let form = state.new_scope_draft.take().unwrap_or_else(|| {
            let paths = state
                .selected_file()
                .map(|file| vec![file])
                .unwrap_or_else(|| uncovered_paths(review));
            let scope = ProposedScanScope {
                id: kuzushi_core::new_run_id("scope"),
                name: "New discovery scope".into(),
                paths,
                rationale: "Operator-defined discovery boundary.".into(),
                shared_dependencies: Vec::new(),
                open_questions: Vec::new(),
            };
            ScopeEditForm::for_scope(ScopeEditKind::Add, &scope)
        });
        state.menu = None;
        state.files = None;
        state.form = Some(form);
        state.scroll = 0;
        state.notice = Some("Review the name, source paths and reason. Save recomputes coverage and clears acceptance; no jobs or model calls. Esc keeps this draft for Add discovery scope.".into());
    }
}

fn uncovered_paths(review: &ScanScopeReview) -> Vec<String> {
    let files = &review.coverage.uncovered_files;
    if files.total == files.files.len() && files.total <= 32 {
        return files.files.clone();
    }
    Vec::new()
}

impl ScopeEditForm {
    pub(super) fn new_discovery_scope(&self) -> anyhow::Result<ScanScopeEdit> {
        let paths = self.path_lines(1)?;
        Ok(ScanScopeEdit::AddScope {
            scope: ProposedScanScope {
                id: self.template.id.clone(),
                name: self.text(0)?,
                paths,
                rationale: self.text(2)?,
                shared_dependencies: Vec::new(),
                open_questions: Vec::new(),
            },
        })
    }
}

pub(super) fn retain_draft(state: &mut ScopeReviewState, form: ScopeEditForm) {
    if form.kind == ScopeEditKind::Add {
        state.new_scope_draft = Some(form);
    }
}

impl ScopeReviewState {
    pub(super) fn selection_for_saved_review(&mut self) -> Option<String> {
        if let Some(form) = self
            .form
            .as_ref()
            .filter(|form| form.kind == ScopeEditKind::Add)
        {
            self.scroll = 0;
            return Some(form.template.id.clone());
        }
        self.selected_id().map(str::to_owned)
    }
}
