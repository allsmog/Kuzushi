use super::*;

impl BatchPriorRun {
    pub(in crate::app::batch_scan) fn pending(run_id: &str) -> Self {
        Self {
            run_id: run_id.into(),
            evidence: ViewDataState::NotRequested,
        }
    }
}

impl BatchScanConfig {
    pub(crate) fn apply_usage_catalogue(&mut self, state: ViewDataState<StudyUsageCatalogueRead>) {
        if self.prior_catalogue == state {
            return;
        }
        if let ViewDataState::Ready(Ok(catalogue)) = &state {
            let mut runs = catalogue
                .run_ids
                .iter()
                .map(|id| {
                    prior_run_named(&self.prior_runs, id)
                        .cloned()
                        .unwrap_or_else(|| BatchPriorRun::pending(id))
                })
                .collect::<Vec<_>>();
            append_named_baseline(&mut runs, &self.prior_runs, self.prior_run_id.as_deref());
            self.prior_runs = runs;
        }
        self.prior_catalogue = state;
    }

    pub(crate) fn apply_selected_usage(&mut self, state: ViewDataState<StudyUsageRunRead>) {
        let Some(id) = &self.prior_run_id else {
            return;
        };
        if let Some(prior) = self.prior_runs.iter_mut().find(|prior| &prior.run_id == id) {
            prior.evidence = state;
        }
    }

    pub(crate) fn reset_usage_loading(&mut self) {
        self.prior_catalogue = ViewDataState::NotRequested;
        for prior in &mut self.prior_runs {
            prior.evidence = ViewDataState::NotRequested;
        }
    }
}

fn append_named_baseline(
    runs: &mut Vec<BatchPriorRun>,
    old: &[BatchPriorRun],
    selected: Option<&str>,
) {
    let Some(id) = selected else {
        return;
    };
    if prior_run_named(runs, id).is_some() {
        return;
    }
    runs.push(
        prior_run_named(old, id)
            .cloned()
            .unwrap_or_else(|| BatchPriorRun::pending(id)),
    );
}
