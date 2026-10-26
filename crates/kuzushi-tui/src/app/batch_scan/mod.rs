mod brief;
mod config;
pub(crate) use brief::{BriefEditor, BriefMode};
mod context_check;
mod context_checkpoint;
mod context_edit;
pub(crate) use context_checkpoint::ContextCheckpointRuntime;
mod context_generation;
mod lesson_followup;
mod lesson_generation;
mod review_study;
pub(crate) use context_generation::StudyContextGeneration;
pub(crate) use review_study::ReviewStudyDraft;
mod context_comparison;
mod context_experiment;
mod context_question;
mod context_regeneration;
mod workflow_proposal;
pub(crate) use context_comparison::{
    ContextComparisonCursor, ContextComparisonView, StudyContextComparison,
};
pub(crate) use context_edit::{
    ContextDraftRecovery, ContextEditDraft, ContextEditEntry, ContextEditMode,
};
mod context_matrix;
mod controller;
mod dfd_study;
mod launch;
mod map_allowance;
mod model_draft_exit;
mod number_edit;
mod resource_picker;
mod results;
pub(crate) use resource_picker::StudyResourcePicker;
mod scope_context;
pub(super) mod scope_study;
mod study_actions;
mod study_context;
mod study_engines;
mod study_failure;
mod study_keys;
mod study_reader;
mod study_source;
pub(crate) use study_source::StudySourceView;
mod study_checkpoint;
mod study_recovery;
mod study_state;
pub(crate) use study_checkpoint::{
    RecoveredStudyDraft, StudyCheckpointRuntime, StudyDraftRecovery,
};
mod usage_hydration;
mod worker_resolution;

pub(crate) use config::{
    BatchScanConfig, BatchScanConfigRow, BATCH_HARD_CAP, DEFAULT_BATCH_TRIALS,
};
pub(crate) use study_context::{StudyContextPicker, StudyContextTextView};
pub(crate) use study_engines::StudyEnginePicker;
pub(crate) use worker_resolution::resolve_batch_workers;

pub(crate) fn is_scan_batch_snapshot(
    snapshot: &kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot,
) -> bool {
    snapshot.kind.as_deref() == Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND)
}

pub(crate) fn is_fixed_study_snapshot(
    snapshot: &kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot,
) -> bool {
    is_scan_batch_snapshot(snapshot)
        || snapshot.kind.as_deref() == Some("context-study")
        || snapshot.kind.as_deref() == Some(kuzushi_core::capabilities::campaign::REVIEW_STUDY_KIND)
        || snapshot.kind.as_deref()
            == Some(kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND)
        || snapshot.kind.as_deref() == Some(kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND)
}
