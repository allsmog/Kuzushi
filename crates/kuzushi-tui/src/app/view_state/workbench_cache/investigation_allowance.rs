use super::*;
use crate::app::view_hydration::InvestigationAllowanceRead;
use std::time::{Duration, Instant};

const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct InvestigationAllowanceCache {
    target: PathBuf,
    key: ViewHydrationKey,
    read_at: Instant,
    state: InvestigationAllowanceRead,
}

impl WorkbenchCache {
    pub(crate) fn cached_investigation_allowance(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<InvestigationAllowanceRead> {
        match self.allowance_cache(target, key) {
            Some(cache) => ViewDataState::Ready(cache.state.clone()),
            None => self.loading_state(target, key),
        }
    }

    pub(super) fn investigation_allowance_needs_refresh(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> bool {
        self.allowance_cache(target, key)
            .is_none_or(|cache| cache.read_at.elapsed() >= REFRESH_INTERVAL)
    }

    pub(super) fn apply_allowance_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        if let ViewHydrationValue::InvestigationAllowance(state) = value {
            self.investigation_allowance = Some(InvestigationAllowanceCache {
                target,
                key,
                read_at: Instant::now(),
                state,
            });
        }
    }

    pub(super) fn record_failed_allowance_read(&mut self, failure: &ViewHydrationFailure) {
        if matches!(failure.key, ViewHydrationKey::InvestigationAllowance { .. }) {
            self.apply_allowance_hydration(
                failure.target.clone(),
                failure.key.clone(),
                ViewHydrationValue::InvestigationAllowance(Err(
                    "Investigation allowance read failed; retrying this read.".into(),
                )),
            );
        }
    }

    fn allowance_cache(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> Option<&InvestigationAllowanceCache> {
        self.investigation_allowance
            .as_ref()
            .filter(|cache| cache.target == target && &cache.key == key)
    }
}

#[cfg(test)]
mod tests;
