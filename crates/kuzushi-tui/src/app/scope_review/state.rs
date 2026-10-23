use crate::app::FieldEditor;
use kuzushi_core::workspace::{
    ScanScopeProposalRef, ScanScopeReview, ScopeCoverageApproval, ScopeFileFilter, ScopeFilePage,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeReviewState {
    pub target: PathBuf,
    pub open: bool,
    pub findings_origin: Option<crate::app::state_transitions::LinkedFindingsOrigin>,
    pub review: Option<Arc<ScanScopeReview>>,
    pub cursor: usize,
    pub tree: super::ScopeTreeState,
    pub study_scope_ids: std::collections::BTreeSet<String>,
    pub scroll: usize,
    pub menu: Option<usize>,
    pub menu_search: Option<FieldEditor>,
    pub merge_target: Option<usize>,
    pub form: Option<ScopeEditForm>,
    pub new_scope_draft: Option<ScopeEditForm>,
    pub accepting: bool,
    pub acknowledgements: ScopeCoverageApproval,
    pub acknowledgement_cursor: usize,
    pub files: Option<ScopeFiles>,
    pub pending: Option<ScopeRequest>,
    pub notice: Option<String>,
}

impl ScopeReviewState {
    pub fn new(target: PathBuf) -> Self {
        Self {
            target,
            open: true,
            findings_origin: None,
            review: None,
            cursor: 0,
            tree: Default::default(),
            study_scope_ids: Default::default(),
            scroll: 0,
            menu: None,
            menu_search: None,
            merge_target: None,
            form: None,
            new_scope_draft: None,
            accepting: false,
            acknowledgements: Default::default(),
            acknowledgement_cursor: 0,
            files: None,
            pending: None,
            notice: None,
        }
    }

    pub fn install(&mut self, review: ScanScopeReview) {
        self.study_scope_ids.retain(|id| {
            review
                .coverage
                .discovery_members
                .get(id)
                .is_some_and(|members| members.total > 0)
        });
        let selected = self
            .selection_for_saved_review()
            .map(|id| super::ScopeTreeRow::Branch(super::ScopeBranch::Scope(id)))
            .or_else(|| self.selected_row());
        self.reconcile_tree(&review);
        self.review = Some(Arc::new(review));
        self.restore_tree_selection(selected);
        self.files = None;
        self.pending = None;
        self.form = None;
        self.menu = None;
        self.menu_search = None;
        self.merge_target = None;
        self.accepting = false;
        self.acknowledgements = Default::default();
        self.notice = None;
    }

    pub fn selected_id(&self) -> Option<&str> {
        let super::ScopeTreeRow::Branch(super::ScopeBranch::Scope(id)) = self.selected_row()?
        else {
            return None;
        };
        scope_ids(self.review.as_deref()?).find(|next| *next == id)
    }

    pub fn row_count(&self) -> usize {
        self.tree_rows().len()
    }

    fn reconcile_tree(&mut self, review: &ScanScopeReview) {
        let same_proposal = self
            .review
            .as_ref()
            .is_some_and(|old| old.reference.proposal_id == review.reference.proposal_id);
        if !same_proposal {
            self.tree = Default::default();
            self.scroll = 0;
            return;
        }
        if self.review.as_ref().is_some_and(|old| {
            old.coverage != review.coverage || old.record.source != review.record.source
        }) {
            self.tree.pages.clear();
        }
        self.tree.expanded.retain(|branch| match branch {
            super::ScopeBranch::Scope(id) => scope_ids(review).any(|next| next == id),
            _ => true,
        });
    }
}

pub(super) fn scope_ids(review: &ScanScopeReview) -> impl Iterator<Item = &str> {
    review
        .record
        .draft
        .scopes
        .iter()
        .chain(review.record.draft.shared_scope.iter())
        .map(|scope| scope.id.as_str())
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeRequest {
    pub operation: String,
    pub reference: Option<ScanScopeProposalRef>,
    pub filter: Option<ScopeFileFilter>,
    pub offset: usize,
    pub tree_branch: Option<super::ScopeBranch>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeFiles {
    pub filter: ScopeFileFilter,
    pub page: ScopeFilePage,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ScopeEditKind {
    Add,
    AiPriorities,
    Rename,
    Split,
    Exclude,
    ExcludePath,
    IncludePath,
    Boundary,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeEditForm {
    pub omit_context: bool,
    pub kind: ScopeEditKind,
    pub template: kuzushi_core::workspace::ProposedScanScope,
    pub child_id_prefix: String,
    pub fields: Vec<(&'static str, FieldEditor)>,
    pub cursor: usize,
}
