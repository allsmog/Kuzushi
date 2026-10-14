use super::*;
use crate::app::view_hydration::FindingReviewSourceRead;

impl WorkbenchCache {
    pub(super) fn record_failed_review_source(&mut self, failure: &ViewHydrationFailure) {
        if matches!(failure.key, ViewHydrationKey::FindingReviewSource { .. }) {
            self.store_finding_review_source(
                failure.target.clone(),
                failure.key.clone(),
                Err("Decision source reader failed. Refresh to retry.".into()),
            );
        }
    }

    pub(crate) fn cached_finding_review_source(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<FindingReviewSourceRead> {
        if let Some(value) = self
            .finding_review_sources
            .get(&(target.to_path_buf(), key.clone()))
        {
            return ViewDataState::Ready(value.clone());
        }
        self.loading_state(target, key)
    }

    pub(super) fn store_finding_review_source(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: FindingReviewSourceRead,
    ) {
        insert_bounded(
            &mut self.finding_review_sources,
            (target, key),
            value,
            MAX_FINDING_TRUTH_CACHE_ENTRIES,
        );
    }
}
