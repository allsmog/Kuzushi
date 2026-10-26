use super::*;

#[derive(Debug, Default)]
pub(super) struct RepositoryIndexCache {
    cached: Option<(PathBuf, Arc<ContextSnapshotView>)>,
}

impl RepositoryIndexCache {
    pub(super) fn cached(&self, target: &Path) -> Option<Arc<ContextSnapshotView>> {
        self.cached
            .as_ref()
            .filter(|(cached, _)| cached == target)
            .map(|(_, view)| Arc::clone(view))
    }

    pub(super) fn store(&mut self, target: PathBuf, view: Arc<ContextSnapshotView>) {
        self.cached = Some((target, view));
    }

    pub(super) fn invalidate(&mut self) {
        self.cached = None;
    }

    pub(super) fn invalidate_path(&mut self, path: &Path) {
        let Some((target, _)) = &self.cached else {
            return;
        };
        let changed = target.join(path);
        if kuzushi_core::context_snapshot_path(target).starts_with(changed) {
            self.invalidate();
        }
    }
}

impl WorkbenchCache {
    pub(crate) fn cached_repository_index(
        &self,
        target: &Path,
    ) -> ViewDataState<Arc<ContextSnapshotView>> {
        if let Some(view) = self.repository_index.cached(target) {
            return ViewDataState::Ready(view);
        }
        self.loading_state(target, &ViewHydrationKey::RepositoryIndex)
    }

    pub(super) fn record_failed_repository_index(&mut self, failure: &ViewHydrationFailure) {
        if failure.key != ViewHydrationKey::RepositoryIndex {
            return;
        }
        let view = crate::app::view_hydration::repository_index::unavailable_view(
            &failure.target,
            "repository index read failed",
        );
        self.repository_index.store(failure.target.clone(), view);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_index_paths_and_ancestors_invalidate_the_target_bound_cache() {
        let root = Path::new("/owned/root");
        let view = Arc::new(crate::app::workspace_context::default_context_snapshot_view(None));
        let mut cache = RepositoryIndexCache::default();
        for path in [
            PathBuf::from(".kuzushi/context-snapshot.json"),
            PathBuf::from(".kuzushi"),
            kuzushi_core::context_snapshot_path(root),
        ] {
            cache.store(root.to_path_buf(), Arc::clone(&view));
            assert!(cache.cached(Path::new("/owned/other")).is_none());
            cache.invalidate_path(Path::new(".kuzushi/v3/runs"));
            assert!(cache.cached(root).is_some());
            cache.invalidate_path(&path);
            assert!(cache.cached(root).is_none(), "{path:?}");
        }
    }
}
