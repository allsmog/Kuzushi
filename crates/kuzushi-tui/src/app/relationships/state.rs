use super::*;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RelationshipsRouteState {
    pub(crate) show_groups: bool,
    pub(crate) groups: FindingGroupsRouteState,
    pub(crate) finding_id: Option<i64>,
    pub(crate) offset: usize,
    pub(crate) cursor: usize,
    pub(crate) note: Option<RelationshipNote>,
    pub(crate) notice: Option<String>,
    pub(crate) selection: Vec<FindingRelationship>,
    pub(crate) bulk: Option<RelationshipBulkReview>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RelationshipNote {
    pub(crate) target: PathBuf,
    pub(crate) relationship: FindingRelationship,
    pub(crate) state: FindingRelationshipState,
    pub(crate) field: FieldEditor,
}

pub(crate) struct RelationshipWrite {
    pub(crate) target: PathBuf,
    pub(crate) draft: RelationshipWriteDraft,
    pub(crate) handle: std::thread::JoinHandle<Result<(), String>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RelationshipBulkStage {
    Review,
    Reason,
    Confirm,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RelationshipBulkReview {
    pub(crate) target: PathBuf,
    pub(crate) records: Vec<FindingRelationship>,
    pub(crate) cursor: usize,
    pub(crate) stage: RelationshipBulkStage,
    pub(crate) state: FindingRelationshipState,
    pub(crate) field: FieldEditor,
    pub(crate) origin_scroll: u16,
    pub(crate) review_scroll: u16,
    pub(crate) inspecting_destination: bool,
    pub(crate) return_from_source: bool,
    pub(crate) source_scroll: u16,
}

#[derive(Debug, Clone)]
pub(crate) enum RelationshipWriteDraft {
    Single(RelationshipNote),
    Batch(RelationshipBulkReview),
}

impl From<RelationshipNote> for RelationshipWriteDraft {
    fn from(note: RelationshipNote) -> Self {
        Self::Single(note)
    }
}
impl std::fmt::Debug for RelationshipWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelationshipWrite")
            .field("target", &self.target)
            .finish()
    }
}
