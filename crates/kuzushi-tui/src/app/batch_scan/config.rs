use super::number_edit::BatchNumberEdit;
use crate::app::{StudyUsageCatalogueRead, StudyUsageRunRead, ViewDataState};
use std::path::Path;
mod usage;

pub(crate) const DEFAULT_BATCH_TRIALS: usize = 3;
pub(crate) const BATCH_HARD_CAP: usize = 50;
pub(super) const MIN_BATCH_TRIALS: usize = 2;
pub(super) const MAX_BATCH_WORKERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchScanConfigRow {
    Trials,
    Workers,
    Engines,
    Context,
    ProviderCalls,
    ReviewCalls,
    Attempts,
    PriorRun,
    Launch,
}

impl BatchScanConfigRow {
    pub(crate) const ALL: [Self; 9] = [
        Self::Trials,
        Self::Workers,
        Self::Engines,
        Self::Context,
        Self::ProviderCalls,
        Self::ReviewCalls,
        Self::Attempts,
        Self::PriorRun,
        Self::Launch,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Trials => "Discovery passes",
            Self::Workers => "Workers",
            Self::Engines => "Discovery engines",
            Self::Context => "Source and context",
            Self::ProviderCalls => "Total calls",
            Self::ReviewCalls => "Protected review",
            Self::Attempts => "Attempts per job",
            Self::PriorRun => "Usage evidence",
            Self::Launch => "Next action",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BatchPriorRun {
    pub(crate) run_id: String,
    pub(crate) evidence: ViewDataState<StudyUsageRunRead>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BatchScanConfig {
    pub(crate) origin: Option<StudyNavigationOrigin>,
    pub(crate) target: std::path::PathBuf,
    pub(crate) trials: usize,
    pub(crate) requested_workers: usize,
    pub(crate) effective_workers: usize,
    pub(crate) worker_clamp_reason: Option<String>,
    pub(crate) prior_run_id: Option<String>,
    pub(crate) prior_runs: Vec<BatchPriorRun>,
    pub(crate) prior_catalogue: ViewDataState<StudyUsageCatalogueRead>,
    pub(crate) cursor: usize,
    pub(crate) study: super::study_state::StudyDraftState,
    pub(crate) detail_scroll: usize,
    pub(crate) notice: Option<String>,
    pub(crate) number_edit: Option<BatchNumberEdit>,
    pub(crate) context_picker: Option<super::StudyContextPicker>,
    pub(crate) engine_picker: Option<super::StudyEnginePicker>,
    pub(crate) context_generation: Option<super::context_generation::StudyContextGeneration>,
}

impl BatchScanConfig {
    pub(crate) fn load(target: &Path, requested_prior_run: Option<&str>) -> Self {
        Self {
            origin: None,
            target: target.to_path_buf(),
            trials: DEFAULT_BATCH_TRIALS,
            requested_workers: 1,
            effective_workers: 1,
            worker_clamp_reason: None,
            prior_run_id: requested_prior_run.map(str::to_owned),
            prior_runs: requested_prior_run
                .map(BatchPriorRun::pending)
                .into_iter()
                .collect(),
            prior_catalogue: ViewDataState::NotRequested,
            cursor: 0,
            study: super::study_state::StudyDraftState::default(),
            detail_scroll: 0,
            notice: None,
            number_edit: None,
            context_picker: None,
            engine_picker: None,
            context_generation: None,
        }
    }

    pub(crate) fn load_for_new_study(target: &Path, requested_prior_run: Option<&str>) -> Self {
        let mut config = Self::load(target, requested_prior_run);
        super::map_allowance::restore_map_allowance(&mut config);
        config
    }

    pub(crate) fn load_for_map_study(target: &Path) -> Self {
        let mut config = Self::load(target, None);
        super::map_allowance::restore_map_history_allowance(&mut config);
        config
    }

    pub(crate) fn selected_row(&self) -> BatchScanConfigRow {
        BatchScanConfigRow::ALL[self.cursor.min(BatchScanConfigRow::ALL.len() - 1)]
    }

    pub(crate) fn move_cursor(&mut self, delta: i64) {
        let last = BatchScanConfigRow::ALL.len() as i64 - 1;
        self.cursor = (self.cursor as i64 + delta).clamp(0, last) as usize;
        self.detail_scroll = 0;
    }

    pub(crate) fn activate_selected(&mut self) -> bool {
        match self.selected_row() {
            BatchScanConfigRow::PriorRun => self.cycle_prior_run(),
            BatchScanConfigRow::Launch => return true,
            row => self.begin_number_edit(row),
        }
        false
    }

    pub(crate) fn cycle_prior_run(&mut self) {
        let previous = self.prior_run_id.clone();
        let next = next_prior_run(&self.prior_runs, self.prior_run_id.as_deref());
        self.prior_run_id = next.map(|prior| prior.run_id.clone());
        self.notice = None;
        if previous != self.prior_run_id && self.study.receipt.is_some() {
            self.study.invalidate_plan();
            self.notice = Some("Usage evidence changed. Prepare a new plan for separate approval; limits, options and existing spending remain.".into());
        }
    }

    pub(crate) fn selected_prior(&self) -> Option<&BatchPriorRun> {
        prior_run_named(&self.prior_runs, self.prior_run_id.as_deref()?)
    }

    pub(crate) fn resource_projection(
        &self,
    ) -> Result<kuzushi_core::capabilities::campaign::StudyResourceProjection, String> {
        let prior = self
            .selected_prior()
            .ok_or("Select usage evidence explicitly.")?;
        let evidence = match &prior.evidence {
            ViewDataState::Ready(value) => value.as_ref().map_err(Clone::clone)?,
            _ => return Err("Historical usage is loading; no projection yet.".into()),
        };
        let receipt = self.study.receipt.as_ref().ok_or(
            "Prepare the draft to compare historical source, context, model and scan options.",
        )?;
        evidence
            .project(
                &receipt.equivalence,
                self.trials,
                self.study.max_job_attempts,
            )
            .map_err(|error| error.to_string())
    }

    pub(crate) fn apply_worker_resolution(
        &mut self,
        effective_workers: usize,
        reason: Option<String>,
    ) {
        self.effective_workers = effective_workers.max(1);
        self.worker_clamp_reason = reason;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyNavigationOrigin {
    pub(crate) view: crate::app::ShellView,
    pub(crate) mode: crate::app::InputMode,
    pub(crate) workbench: crate::app::WorkbenchRouteState,
    pub(crate) scope_review: bool,
}

fn prior_run_named<'a>(runs: &'a [BatchPriorRun], run_id: &str) -> Option<&'a BatchPriorRun> {
    runs.iter().find(|prior| prior.run_id == run_id)
}

fn next_prior_run<'a>(
    runs: &'a [BatchPriorRun],
    selected: Option<&str>,
) -> Option<&'a BatchPriorRun> {
    let next_index = selected
        .and_then(|id| runs.iter().position(|prior| prior.run_id == id))
        .map(|index| index + 1)
        .unwrap_or(0);
    runs.get(next_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::RunSummary;
    mod resources;

    #[test]
    fn defaults_require_an_explicit_allowance() {
        let target = tempfile::tempdir().unwrap();
        let config = BatchScanConfig::load(target.path(), None);

        assert_eq!(config.trials, 3);
        assert!(config.resource_projection().is_err());
        assert_eq!(config.study.max_provider_calls, None);
        assert_eq!(config.study.protected_review_calls, None);
        assert_eq!(config.study.max_job_attempts, 1);
        assert!(!config.study.approved());
    }

    #[test]
    fn named_completed_cost_remains_historical_without_verified_conditions() {
        let target = tempfile::tempdir().unwrap();
        let summary = RunSummary::running(
            "scan-prior",
            "tool",
            Some("sast:scan".to_string()),
            target.path().display().to_string(),
        )
        .complete()
        .with_cost(Some(0.25));
        kuzushi_core::write_run_summary(target.path(), &summary).unwrap();

        let mut config = BatchScanConfig::load(target.path(), Some("scan-prior"));
        config.prior_runs[0].evidence = ViewDataState::Ready(
            kuzushi_core::capabilities::campaign::load_named_scan_usage(
                target.path(),
                "scan-prior",
            )
            .map_err(|error| error.to_string()),
        );

        assert_eq!(config.prior_run_id.as_deref(), Some("scan-prior"));
        let ViewDataState::Ready(Ok(evidence)) = &config.selected_prior().unwrap().evidence else {
            panic!("missing evidence")
        };
        assert_eq!(evidence.cost_usd, Some(0.25));
        assert!(config.resource_projection().is_err());
    }

    #[test]
    fn incomplete_or_wrong_tool_prior_never_creates_a_projection() {
        let target = tempfile::tempdir().unwrap();
        let summary = RunSummary::running(
            "agent-prior",
            "tool",
            Some("agent:ask".to_string()),
            target.path().display().to_string(),
        )
        .complete()
        .with_cost(Some(0.25));
        kuzushi_core::write_run_summary(target.path(), &summary).unwrap();

        let mut config = BatchScanConfig::load(target.path(), Some("agent-prior"));
        config.prior_runs[0].evidence = ViewDataState::Ready(
            kuzushi_core::capabilities::campaign::load_named_scan_usage(
                target.path(),
                "agent-prior",
            )
            .map_err(|error| error.to_string()),
        );

        assert!(config.resource_projection().is_err());
        assert!(
            crate::ui_view_models::study_config::study_resource_lines(&config)
                .join("\n")
                .contains("Historical usage unavailable")
        );
    }

    #[test]
    fn unresolved_provider_spend_never_creates_an_exact_projection() {
        let root = tempfile::tempdir().unwrap();
        let mut summary = RunSummary::running(
            "scan-unresolved",
            "tool",
            Some("sast:scan".to_string()),
            ".",
        )
        .complete()
        .with_cost(Some(0.25));
        summary.provider_spend_unresolved = true;

        let evidence = kuzushi_core::capabilities::campaign::load_scan_resource_evidence(
            root.path(),
            &summary,
        )
        .unwrap();
        assert_eq!(evidence.cost_usd, None);
    }
}
