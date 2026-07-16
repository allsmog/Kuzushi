use std::sync::atomic::{AtomicU64, Ordering};

static WRITER_SATURATION_COUNT: AtomicU64 = AtomicU64::new(0);
static COALESCED_PROGRESS_COUNT: AtomicU64 = AtomicU64::new(0);
static DEGRADED_REPLAY_COUNT: AtomicU64 = AtomicU64::new(0);
static LEGACY_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLifecycleMetricsSnapshot {
    pub writer_saturation_count: u64,
    pub coalesced_progress_count: u64,
    pub degraded_replay_count: u64,
    pub legacy_fallback_count: u64,
}

pub fn run_lifecycle_metrics_snapshot() -> RunLifecycleMetricsSnapshot {
    RunLifecycleMetricsSnapshot {
        writer_saturation_count: WRITER_SATURATION_COUNT.load(Ordering::Relaxed),
        coalesced_progress_count: COALESCED_PROGRESS_COUNT.load(Ordering::Relaxed),
        degraded_replay_count: DEGRADED_REPLAY_COUNT.load(Ordering::Relaxed),
        legacy_fallback_count: LEGACY_FALLBACK_COUNT.load(Ordering::Relaxed),
    }
}

pub(crate) fn record_writer_saturation() {
    WRITER_SATURATION_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_coalesced_progress(count: u64) {
    COALESCED_PROGRESS_COUNT.fetch_add(count, Ordering::Relaxed);
}

pub(crate) fn record_degraded_replay() {
    DEGRADED_REPLAY_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_legacy_fallback() {
    LEGACY_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
}
