mod config;
mod controller;
mod launch;
mod number_edit;
mod worker_resolution;

pub(crate) use config::{
    BatchScanConfig, BatchScanConfigRow, BATCH_HARD_CAP, BATCH_REVIEW_THRESHOLD,
    DEFAULT_BATCH_TRIALS,
};
pub(crate) use worker_resolution::resolve_batch_workers;

pub(crate) fn is_scan_batch_snapshot(
    snapshot: &kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot,
) -> bool {
    snapshot.kind.as_deref() == Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND)
}
