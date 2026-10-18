use super::*;
use crate::app::view_hydration::ScanStudyProgressRead;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct ScanStudyProgressCache {
    target: PathBuf,
    key: ViewHydrationKey,
    read_at: Instant,
    state: ScanStudyProgressRead,
}

impl WorkbenchCache {
    pub(crate) fn cached_scan_study_progress(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<ScanStudyProgressRead> {
        match self.scan_study_cache(target, key) {
            Some(cache) => ViewDataState::Ready(cache.state.clone()),
            None => self.loading_state(target, key),
        }
    }

    pub(super) fn scan_study_needs_refresh(&self, target: &Path, key: &ViewHydrationKey) -> bool {
        self.scan_study_cache(target, key)
            .is_none_or(|cache| cache.read_at.elapsed() >= Duration::from_secs(2))
    }

    pub(super) fn apply_scan_study_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        if let ViewHydrationValue::ScanStudyProgress(state) = value {
            self.scan_study_progress = Some(ScanStudyProgressCache {
                target,
                key,
                read_at: Instant::now(),
                state,
            });
        }
    }

    pub(super) fn record_failed_scan_study(&mut self, failure: &ViewHydrationFailure) {
        if matches!(failure.key, ViewHydrationKey::ScanStudyProgress { .. }) {
            self.apply_scan_study_hydration(
                failure.target.clone(),
                failure.key.clone(),
                ViewHydrationValue::ScanStudyProgress(Err(
                    "Study queue unavailable; retrying this read.".into(),
                )),
            );
        }
    }

    fn scan_study_cache(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> Option<&ScanStudyProgressCache> {
        self.scan_study_progress
            .as_ref()
            .filter(|cache| cache.target == target && &cache.key == key)
    }
}

#[cfg(test)]
mod tests;
