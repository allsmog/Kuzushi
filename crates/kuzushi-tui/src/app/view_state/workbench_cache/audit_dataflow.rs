use super::*;

/// Cached deep-auditor dataflow evidence, keyed by target + finding
/// fingerprint. Mirrors `FindingPatchTruthCache`: one sqlite read per finding,
/// invalidated whenever findings change so a rescan never shows stale
/// citations.
#[derive(Debug, Default)]
pub(super) struct FindingAuditDataflowCache {
    entries: BTreeMap<FindingAuditDataflowCacheKey, FindingAuditDataflowState>,
}

impl FindingAuditDataflowCache {
    pub(super) fn get(
        &self,
        key: &FindingAuditDataflowCacheKey,
    ) -> Option<FindingAuditDataflowState> {
        self.entries.get(key).cloned()
    }

    pub(super) fn store(
        &mut self,
        key: FindingAuditDataflowCacheKey,
        state: FindingAuditDataflowState,
    ) {
        insert_bounded(
            &mut self.entries,
            key,
            state,
            MAX_FINDING_TRUTH_CACHE_ENTRIES,
        );
    }

    pub(super) fn invalidate(&mut self, fingerprint: Option<&str>) {
        match fingerprint {
            Some(fingerprint) => self.entries.retain(|key, _| key.fingerprint != fingerprint),
            None => self.entries.clear(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FindingAuditDataflowCacheKey {
    target: PathBuf,
    fingerprint: String,
}

impl FindingAuditDataflowCacheKey {
    fn new(target: &Path, fingerprint: &str) -> Self {
        Self {
            target: target.to_path_buf(),
            fingerprint: fingerprint.to_string(),
        }
    }
}

impl WorkbenchCache {
    pub(crate) fn cached_finding_audit_dataflow(
        &self,
        target: &Path,
        fingerprint: &str,
    ) -> ViewDataState<FindingAuditDataflowState> {
        let cache_key = FindingAuditDataflowCacheKey::new(target, fingerprint);
        if let Some(state) = self.finding_audit_dataflow.get(&cache_key) {
            return ViewDataState::Ready(state);
        }
        self.loading_state(
            target,
            &ViewHydrationKey::FindingAuditDataflow {
                fingerprint: fingerprint.to_string(),
            },
        )
    }

    pub(crate) fn store_finding_audit_dataflow(
        &mut self,
        target: &Path,
        fingerprint: &str,
        state: FindingAuditDataflowState,
    ) {
        let key = FindingAuditDataflowCacheKey::new(target, fingerprint);
        self.finding_audit_dataflow.store(key, state);
    }
}
