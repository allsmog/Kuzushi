mod brief;
mod config;
pub(crate) use brief::{BriefEditor, BriefMode};
mod context_check;
mod context_edit;
mod context_generation;
mod lesson_generation;
pub(crate) use context_generation::StudyContextGeneration;
mod context_comparison;
mod context_experiment;
mod context_regeneration;
pub(crate) use context_comparison::StudyContextComparison;
pub(crate) use context_edit::{ContextEditDraft, ContextEditEntry, ContextEditMode};
mod context_matrix;
mod controller;
mod launch;
mod map_allowance;
mod number_edit;
mod resource_picker;
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
mod study_recovery;
mod study_state;
mod usage_hydration;
mod worker_resolution;

pub(crate) use config::{
    BatchScanConfig, BatchScanConfigRow, BATCH_HARD_CAP, DEFAULT_BATCH_TRIALS,
};
pub(crate) use study_context::StudyContextPicker;
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
        || snapshot.kind.as_deref()
            == Some(kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND)
        || snapshot.kind.as_deref() == Some(kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND)
}
