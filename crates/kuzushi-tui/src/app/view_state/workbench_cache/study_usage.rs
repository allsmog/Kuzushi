use super::*;

impl WorkbenchCache {
    pub(super) fn record_failed_study_usage(&mut self, failure: &ViewHydrationFailure) {
        let error = failure.message("Usage reader failed. Refresh to retry.");
        let value = match &failure.key {
            ViewHydrationKey::StudyHistory => ViewHydrationValue::StudyHistory(Err(error)),
            ViewHydrationKey::StudyUsageCatalogue => {
                ViewHydrationValue::StudyUsageCatalogue(Err(error))
            }
            ViewHydrationKey::StudyUsageRun { .. } => ViewHydrationValue::StudyUsageRun(Err(error)),
            ViewHydrationKey::ContextMatrixReport { .. } => {
                ViewHydrationValue::ContextMatrixReport(Err(failure
                    .message("Matrix reader failed. r refreshes results without starting work.")))
            }
            _ => return,
        };
        self.apply_study_usage_hydration(failure.target.clone(), failure.key.clone(), value);
    }

    pub(crate) fn cached_study_usage_catalogue(
        &self,
        target: &Path,
    ) -> ViewDataState<StudyUsageCatalogueRead> {
        if let Some((_, state)) = self
            .study_usage_catalogue
            .as_ref()
            .filter(|(root, _)| root == target)
        {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(target, &ViewHydrationKey::StudyUsageCatalogue)
    }

    pub(crate) fn cached_study_usage_run(
        &self,
        target: &Path,
        run_id: &str,
    ) -> ViewDataState<StudyUsageRunRead> {
        if let Some(state) = self
            .study_usage_runs
            .get(&(target.to_path_buf(), run_id.into()))
        {
            return ViewDataState::Ready(state.clone());
        }
        self.loading_state(
            target,
            &ViewHydrationKey::StudyUsageRun {
                run_id: run_id.into(),
            },
        )
    }

    pub(super) fn study_usage_hydration_needed(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> bool {
        match key {
            ViewHydrationKey::StudyHistory => self.cached_study_history(target).is_not_requested(),
            ViewHydrationKey::ContextMatrixReport { .. } => {
                self.cached_matrix_report(target, key).is_not_requested()
            }
            ViewHydrationKey::StudyUsageCatalogue => {
                self.cached_study_usage_catalogue(target).is_not_requested()
            }
            ViewHydrationKey::StudyUsageRun { run_id } => self
                .cached_study_usage_run(target, run_id)
                .is_not_requested(),
            _ => false,
        }
    }

    pub(super) fn apply_study_usage_hydration(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: ViewHydrationValue,
    ) {
        match (key, value) {
            (ViewHydrationKey::StudyHistory, ViewHydrationValue::StudyHistory(state)) => {
                self.study_history = Some((target, state))
            }
            (
                key @ ViewHydrationKey::ContextMatrixReport { .. },
                ViewHydrationValue::ContextMatrixReport(state),
            ) => insert_bounded(
                &mut self.matrix_reports,
                (target, key),
                state,
                MAX_RUN_CACHE_ENTRIES,
            ),
            (
                ViewHydrationKey::StudyUsageCatalogue,
                ViewHydrationValue::StudyUsageCatalogue(state),
            ) => self.study_usage_catalogue = Some((target, state)),
            (
                ViewHydrationKey::StudyUsageRun { run_id },
                ViewHydrationValue::StudyUsageRun(state),
            ) => insert_bounded(
                &mut self.study_usage_runs,
                (target, run_id),
                state,
                MAX_RUN_CACHE_ENTRIES,
            ),
            _ => {}
        }
    }

    pub(crate) fn invalidate_study_usage(&mut self, target: &Path) {
        self.invalidate_study_history(target);
        if self
            .study_usage_catalogue
            .as_ref()
            .is_some_and(|(root, _)| root == target)
        {
            self.study_usage_catalogue = None;
        }
        self.study_usage_runs.retain(|(root, _), _| root != target);
        self.matrix_reports.retain(|(root, _), _| root != target);
    }

    pub(crate) fn cached_matrix_report(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<Result<kuzushi_core::findings::ContextMatrixOccurrenceReport, String>> {
        if let Some(value) = self.matrix_reports.get(&(target.into(), key.clone())) {
            return ViewDataState::Ready(value.clone());
        }
        self.loading_state(target, key)
    }
}
