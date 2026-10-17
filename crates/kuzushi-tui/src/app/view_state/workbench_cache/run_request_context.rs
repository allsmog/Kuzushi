use super::*;
use crate::app::RunRequestContextRead;

impl WorkbenchCache {
    pub(crate) fn cached_run_request_context(
        &self,
        target: &Path,
        run_id: &str,
    ) -> ViewDataState<RunRequestContextRead> {
        if let Some((_, _, state)) = self
            .run_request_context
            .as_ref()
            .filter(|(root, id, _)| root == target && id == run_id)
        {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::RunRequestContext {
                run_id: run_id.into(),
            },
        )
    }

    pub(crate) fn invalidate_run_request_context(&mut self) {
        self.run_request_context = None;
    }

    pub(super) fn store_run_request_context(
        &mut self,
        target: PathBuf,
        run_id: String,
        state: RunRequestContextRead,
    ) {
        self.run_request_context = Some((target, run_id, state));
    }
}
