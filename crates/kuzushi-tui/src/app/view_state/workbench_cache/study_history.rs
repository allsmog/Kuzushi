use super::*;

impl WorkbenchCache {
    pub(crate) fn cached_study_history(&self, target: &Path) -> ViewDataState<StudyHistoryRead> {
        if let Some((_, state)) = self
            .study_history
            .as_ref()
            .filter(|(root, _)| root == target)
        {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::StudyHistory)
    }

    pub(crate) fn invalidate_study_history(&mut self, target: &Path) {
        if self
            .study_history
            .as_ref()
            .is_some_and(|(root, _)| root == target)
        {
            self.study_history = None;
        }
    }
}
