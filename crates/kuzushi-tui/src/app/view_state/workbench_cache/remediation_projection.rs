use super::*;

#[derive(Debug, Default)]
pub(super) struct FindingPatchTruthCache {
    entries: BTreeMap<FindingPatchTruthCacheKey, FindingPatchTruthState>,
}

impl FindingPatchTruthCache {
    pub(super) fn get(&self, key: &FindingPatchTruthCacheKey) -> Option<FindingPatchTruthState> {
        self.entries.get(key).cloned()
    }

    pub(super) fn store(&mut self, key: FindingPatchTruthCacheKey, state: FindingPatchTruthState) {
        self.entries.insert(key, state);
    }

    pub(super) fn invalidate(&mut self, fingerprint: Option<&str>) {
        match fingerprint {
            Some(fingerprint) => self.entries.retain(|key, _| key.fingerprint != fingerprint),
            None => self.entries.clear(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FindingPatchTruthCacheKey {
    target: PathBuf,
    fingerprint: String,
    finding_scan_id: Option<String>,
    target_revision: Option<String>,
}

impl FindingPatchTruthCacheKey {
    fn new(
        target: &Path,
        fingerprint: &str,
        finding_scan_id: Option<&str>,
        target_revision: Option<&str>,
    ) -> Self {
        Self {
            target: target.to_path_buf(),
            fingerprint: fingerprint.to_string(),
            finding_scan_id: finding_scan_id.map(str::to_string),
            target_revision: target_revision.map(str::to_string),
        }
    }
}

impl WorkbenchCache {
    pub(crate) fn cached_finding_patch_truth(
        &self,
        target: &Path,
        fingerprint: &str,
        finding_scan_id: Option<&str>,
        target_revision: Option<&str>,
    ) -> ViewDataState<FindingPatchTruthState> {
        let cache_key =
            FindingPatchTruthCacheKey::new(target, fingerprint, finding_scan_id, target_revision);
        if let Some(state) = self.finding_patch_truth.get(&cache_key) {
            return ViewDataState::Ready(state);
        }
        self.loading_state(
            target,
            &ViewHydrationKey::FindingPatchTruth {
                fingerprint: fingerprint.to_string(),
                finding_scan_id: finding_scan_id.map(str::to_string),
                target_revision: target_revision.map(str::to_string),
            },
        )
    }

    pub(crate) fn store_finding_patch_truth(
        &mut self,
        target: &Path,
        fingerprint: &str,
        finding_scan_id: Option<&str>,
        target_revision: Option<&str>,
        state: FindingPatchTruthState,
    ) {
        let key =
            FindingPatchTruthCacheKey::new(target, fingerprint, finding_scan_id, target_revision);
        self.finding_patch_truth.store(key, state);
    }

    pub(crate) fn invalidate_finding_patch_truth(&mut self, fingerprint: Option<&str>) {
        self.finding_patch_truth.invalidate(fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_binds_target_revision_and_finding_generation() {
        let target = Path::new("/target");
        let key = FindingPatchTruthCacheKey::new(
            target,
            "fingerprint",
            Some("scan-1"),
            Some("revision-1"),
        );

        assert_ne!(
            key,
            FindingPatchTruthCacheKey::new(
                target,
                "fingerprint",
                Some("scan-2"),
                Some("revision-1")
            )
        );
        assert_ne!(
            key,
            FindingPatchTruthCacheKey::new(
                target,
                "fingerprint",
                Some("scan-1"),
                Some("revision-2")
            )
        );
        assert_ne!(
            key,
            FindingPatchTruthCacheKey::new(
                Path::new("/other"),
                "fingerprint",
                Some("scan-1"),
                Some("revision-1")
            )
        );
    }

    #[test]
    fn fingerprint_invalidation_keeps_unrelated_truth() {
        let target = Path::new("/target");
        let mut cache = WorkbenchCache::default();
        cache.store_finding_patch_truth(
            target,
            "first",
            Some("scan"),
            Some("revision"),
            FindingPatchTruthState::Missing,
        );
        cache.store_finding_patch_truth(
            target,
            "second",
            Some("scan"),
            Some("revision"),
            FindingPatchTruthState::Missing,
        );

        cache.invalidate_finding_patch_truth(Some("first"));

        assert!(cache
            .cached_finding_patch_truth(target, "first", Some("scan"), Some("revision"))
            .is_not_requested());
        assert_eq!(
            cache.cached_finding_patch_truth(target, "second", Some("scan"), Some("revision")),
            ViewDataState::Ready(FindingPatchTruthState::Missing)
        );
    }
}
