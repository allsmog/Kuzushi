use crate::app::FieldEditor;
use kuzushi_core::workspace::{
    ScanScopeProposalRef, ScanScopeReview, ScopeCoverageApproval, ScopeFileFilter, ScopeFilePage,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeReviewState {
    pub target: PathBuf,
    pub open: bool,
    pub review: Option<Arc<ScanScopeReview>>,
    pub cursor: usize,
    pub study_scope_ids: std::collections::BTreeSet<String>,
    pub scroll: usize,
    pub menu: Option<usize>,
    pub merge_target: Option<usize>,
    pub form: Option<ScopeEditForm>,
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
            review: None,
            cursor: 0,
            study_scope_ids: Default::default(),
            scroll: 0,
            menu: None,
            merge_target: None,
            form: None,
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
        let selected = self.selected_id().map(str::to_owned);
        self.cursor = selected
            .and_then(|id| scope_ids(&review).position(|next| next == id))
            .unwrap_or(0);
        self.review = Some(Arc::new(review));
        self.files = None;
        self.pending = None;
        self.form = None;
        self.menu = None;
        self.merge_target = None;
        self.accepting = false;
        self.acknowledgements = Default::default();
        self.notice = None;
    }

    pub fn selected_id(&self) -> Option<&str> {
        scope_ids(self.review.as_deref()?).nth(self.cursor)
    }

    pub fn row_count(&self) -> usize {
        self.review.as_ref().map_or(0, |r| {
            r.record.draft.scopes.len() + usize::from(r.record.draft.shared_scope.is_some()) + 3
        })
    }
}

fn scope_ids(review: &ScanScopeReview) -> impl Iterator<Item = &str> {
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
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScopeFiles {
    pub filter: ScopeFileFilter,
    pub page: ScopeFilePage,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ScopeEditKind {
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
