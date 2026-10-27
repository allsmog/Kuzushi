use super::*;

pub(super) fn read(target: &Path) -> Arc<ContextSnapshotView> {
    let path = kuzushi_core::context_snapshot_path(target);
    match crate::app::workspace_context::load_context_snapshot_view(path) {
        Ok(view) => Arc::new(view),
        Err(error) => unavailable_view(target, &format!("{error:#}")),
    }
}

pub(in crate::app) fn unavailable_view(target: &Path, error: &str) -> Arc<ContextSnapshotView> {
    let mut view = crate::app::workspace_context::default_context_snapshot_view(Some(
        kuzushi_core::context_snapshot_path(target),
    ));
    view.status = format!("unavailable: {error}. Use context status to retry the index read.");
    Arc::new(view)
}

pub(super) fn drain_updates_index(drain: &ViewHydrationDrain) -> bool {
    drain
        .results
        .iter()
        .map(|result| &result.key)
        .chain(drain.failures.iter().map(|failure| &failure.key))
        .any(|key| *key == ViewHydrationKey::RepositoryIndex)
}

impl ShellApp {
    pub(super) fn apply_ready_repository_index(&mut self) {
        let Some(target) = self.target() else {
            return;
        };
        let state = self
            .workbench_cache()
            .borrow()
            .cached_repository_index(target);
        if let ViewDataState::Ready(view) = state {
            self.domain_mut().set_context_view((*view).clone());
        }
    }
}
