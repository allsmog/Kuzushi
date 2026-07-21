use super::*;

/// Cache of scanned-time snippet windows keyed by finding identity and the
/// exact hydration inputs, so browsing findings never re-reads the store or
/// blob objects per frame.
#[derive(Debug, Default)]
pub(super) struct ScannedSnippetCache {
    entries: BTreeMap<ScannedSnippetCacheKey, ScannedSnippetState>,
}

impl ScannedSnippetCache {
    pub(super) fn get(&self, key: &ScannedSnippetCacheKey) -> Option<ScannedSnippetState> {
        self.entries.get(key).cloned()
    }

    pub(super) fn store(&mut self, key: ScannedSnippetCacheKey, state: ScannedSnippetState) {
        self.entries.insert(key, state);
    }

    pub(super) fn invalidate(&mut self) {
        self.entries.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ScannedSnippetCacheKey {
    target: PathBuf,
    stable_fp: String,
    scan_id: Option<String>,
    focus_line: u32,
}

impl ScannedSnippetCacheKey {
    fn new(target: &Path, stable_fp: &str, scan_id: Option<&str>, focus_line: u32) -> Self {
        Self {
            target: target.to_path_buf(),
            stable_fp: stable_fp.to_string(),
            scan_id: scan_id.map(str::to_string),
            focus_line,
        }
    }
}

impl WorkbenchCache {
    pub(crate) fn cached_scanned_snippet(
        &self,
        target: &Path,
        stable_fp: &str,
        scan_id: Option<&str>,
        focus_line: u32,
    ) -> ViewDataState<ScannedSnippetState> {
        let cache_key = ScannedSnippetCacheKey::new(target, stable_fp, scan_id, focus_line);
        if let Some(state) = self.scanned_snippets.get(&cache_key) {
            return ViewDataState::Ready(state);
        }
        self.loading_state(
            target,
            &ViewHydrationKey::ScannedSnippet {
                stable_fp: stable_fp.to_string(),
                scan_id: scan_id.map(str::to_string),
                focus_line,
            },
        )
    }

    pub(crate) fn store_scanned_snippet(
        &mut self,
        target: &Path,
        stable_fp: &str,
        scan_id: Option<&str>,
        focus_line: u32,
        state: ScannedSnippetState,
    ) {
        let key = ScannedSnippetCacheKey::new(target, stable_fp, scan_id, focus_line);
        self.scanned_snippets.store(key, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::ScannedSnippetWindow;

    #[test]
    fn cache_round_trips_and_clears_on_invalidate() {
        let target = Path::new("/target");
        let mut cache = WorkbenchCache::default();
        let window = ScannedSnippetWindow {
            start_line: 1,
            focus_line: 2,
            lines: vec!["fn main() {}".to_string()],
        };
        cache.store_scanned_snippet(
            target,
            "identity",
            Some("scan-1"),
            2,
            ScannedSnippetState::Ready(window.clone()),
        );

        assert_eq!(
            cache.cached_scanned_snippet(target, "identity", Some("scan-1"), 2),
            ViewDataState::Ready(ScannedSnippetState::Ready(window))
        );
        assert!(cache
            .cached_scanned_snippet(target, "identity", Some("scan-2"), 2)
            .is_not_requested());

        cache.scanned_snippets.invalidate();
        assert!(cache
            .cached_scanned_snippet(target, "identity", Some("scan-1"), 2)
            .is_not_requested());
    }
}
