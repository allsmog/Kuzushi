mod config;
mod context_generation;
mod controller;
mod launch;
mod number_edit;
mod study_actions;
mod study_context;
mod study_keys;
mod study_recovery;
mod study_state;
mod worker_resolution;

pub(crate) use config::{
    BatchScanConfig, BatchScanConfigRow, BATCH_HARD_CAP, DEFAULT_BATCH_TRIALS,
};
pub(crate) use study_context::StudyContextPicker;
pub(crate) use worker_resolution::resolve_batch_workers;

pub(crate) fn is_scan_batch_snapshot(
    snapshot: &kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot,
) -> bool {
    snapshot.kind.as_deref() == Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND)
}

pub(crate) fn is_fixed_study_snapshot(
    snapshot: &kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot,
) -> bool {
    is_scan_batch_snapshot(snapshot) || snapshot.kind.as_deref() == Some("context-study")
}
