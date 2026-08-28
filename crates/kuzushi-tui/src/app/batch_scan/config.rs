use kuzushi_core::RunSummary;
use std::path::Path;

pub(crate) const DEFAULT_BATCH_TRIALS: usize = 3;
pub(crate) const BATCH_REVIEW_THRESHOLD: usize = 10;
pub(crate) const BATCH_HARD_CAP: usize = 50;
const MIN_BATCH_TRIALS: usize = 2;
const MAX_BATCH_WORKERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchScanConfigRow {
    Trials,
    Workers,
    PriorRun,
    Launch,
}

impl BatchScanConfigRow {
    const ALL: [Self; 4] = [Self::Trials, Self::Workers, Self::PriorRun, Self::Launch];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Trials => "Logical trials",
            Self::Workers => "Parallel workers",
            Self::PriorRun => "Cost evidence",
            Self::Launch => "Review and launch",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BatchPriorRun {
    pub(crate) run_id: String,
    pub(crate) cost_usd: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BatchScanConfig {
    pub(crate) trials: usize,
    pub(crate) requested_workers: usize,
    pub(crate) effective_workers: usize,
    pub(crate) worker_clamp_reason: Option<String>,
    pub(crate) prior_run_id: Option<String>,
    pub(crate) prior_run_cost_usd: Option<f64>,
    pub(crate) prior_runs: Vec<BatchPriorRun>,
    pub(crate) cursor: usize,
    pub(crate) review_armed: bool,
    pub(crate) notice: Option<String>,
}

impl BatchScanConfig {
    pub(crate) fn load(target: &Path, requested_prior_run: Option<&str>) -> Self {
        let prior_runs = exact_prior_scan_runs(target);
        let requested = requested_prior_run.and_then(|id| prior_run_named(&prior_runs, id));
        let notice = requested_prior_run
            .filter(|_| requested.is_none())
            .map(unavailable_prior_notice);
        Self {
            trials: DEFAULT_BATCH_TRIALS,
            requested_workers: 1,
            effective_workers: 1,
            worker_clamp_reason: None,
            prior_run_id: requested.map(|prior| prior.run_id.clone()),
            prior_run_cost_usd: requested.map(|prior| prior.cost_usd),
            prior_runs,
            cursor: 0,
            review_armed: false,
            notice,
        }
    }

    pub(crate) fn selected_row(&self) -> BatchScanConfigRow {
        BatchScanConfigRow::ALL[self.cursor.min(BatchScanConfigRow::ALL.len() - 1)]
    }

    pub(crate) fn move_cursor(&mut self, delta: i64) {
        let last = BatchScanConfigRow::ALL.len() as i64 - 1;
        self.cursor = (self.cursor as i64 + delta).clamp(0, last) as usize;
    }

    pub(crate) fn activate_selected(&mut self) -> bool {
        match self.selected_row() {
            BatchScanConfigRow::Trials => self.cycle_trials(),
            BatchScanConfigRow::Workers => self.cycle_workers(),
            BatchScanConfigRow::PriorRun => self.cycle_prior_run(),
            BatchScanConfigRow::Launch => return true,
        }
        false
    }

    pub(crate) fn cycle_trials(&mut self) {
        self.trials = cycle(self.trials, MIN_BATCH_TRIALS, BATCH_HARD_CAP);
        self.disarm_review();
    }

    pub(crate) fn cycle_workers(&mut self) {
        self.requested_workers = cycle(self.requested_workers, 1, MAX_BATCH_WORKERS);
        self.disarm_review();
    }

    pub(crate) fn cycle_prior_run(&mut self) {
        let next = next_prior_run(&self.prior_runs, self.prior_run_id.as_deref());
        self.prior_run_id = next.map(|prior| prior.run_id.clone());
        self.prior_run_cost_usd = next.map(|prior| prior.cost_usd);
        self.disarm_review();
    }

    pub(crate) fn projected_cost_usd(&self) -> Option<f64> {
        self.prior_run_cost_usd
            .map(|per_trial| per_trial * self.trials as f64)
    }

    pub(crate) fn needs_large_batch_review(&self) -> bool {
        self.trials > BATCH_REVIEW_THRESHOLD
    }

    pub(crate) fn arm_review(&mut self) {
        self.review_armed = true;
        self.notice = Some(format!(
            "{} trials exceeds the review threshold of {} — launch again to confirm",
            self.trials, BATCH_REVIEW_THRESHOLD
        ));
    }

    pub(crate) fn disarm_review(&mut self) {
        self.review_armed = false;
        self.notice = None;
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

fn cycle(current: usize, minimum: usize, maximum: usize) -> usize {
    if current >= maximum {
        minimum
    } else {
        current + 1
    }
}

fn exact_prior_scan_runs(target: &Path) -> Vec<BatchPriorRun> {
    kuzushi_core::list_run_summaries(target)
        .unwrap_or_default()
        .into_iter()
        .filter_map(exact_prior_scan_run)
        .collect()
}

fn exact_prior_scan_run(summary: RunSummary) -> Option<BatchPriorRun> {
    if !is_exact_completed_scan(&summary) {
        return None;
    }
    let cost_usd = summary
        .cost_usd
        .filter(|cost| cost.is_finite() && *cost >= 0.0)?;
    Some(BatchPriorRun {
        run_id: summary.run_id,
        cost_usd,
    })
}

fn is_exact_completed_scan(summary: &RunSummary) -> bool {
    summary.status == "completed"
        && summary.tool.as_deref() == Some("sast:scan")
        && !summary.provider_spend_unresolved
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

fn unavailable_prior_notice(run_id: &str) -> String {
    format!("prior run {run_id:?} has no exact completed sast:scan cost; projection withheld")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_large_batch_review_are_explicit() {
        let target = tempfile::tempdir().unwrap();
        let mut config = BatchScanConfig::load(target.path(), None);

        assert_eq!(config.trials, 3);
        assert_eq!(config.projected_cost_usd(), None);
        config.trials = 11;
        assert!(config.needs_large_batch_review());
        assert!(!config.review_armed);
        config.arm_review();
        assert!(config.review_armed);
    }

    #[test]
    fn trial_control_wraps_at_the_tui_hard_cap() {
        let target = tempfile::tempdir().unwrap();
        let mut config = BatchScanConfig::load(target.path(), None);
        config.trials = BATCH_HARD_CAP;

        config.cycle_trials();

        assert_eq!(config.trials, MIN_BATCH_TRIALS);
    }

    #[test]
    fn projection_requires_an_exact_named_prior_scan_run() {
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

        let config = BatchScanConfig::load(target.path(), Some("scan-prior"));

        assert_eq!(config.prior_run_id.as_deref(), Some("scan-prior"));
        assert_eq!(config.projected_cost_usd(), Some(0.75));
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

        let config = BatchScanConfig::load(target.path(), Some("agent-prior"));

        assert_eq!(config.projected_cost_usd(), None);
        assert!(config
            .notice
            .as_deref()
            .unwrap()
            .contains("projection withheld"));
    }

    #[test]
    fn unresolved_provider_spend_never_creates_an_exact_projection() {
        let mut summary = RunSummary::running(
            "scan-unresolved",
            "tool",
            Some("sast:scan".to_string()),
            ".",
        )
        .complete()
        .with_cost(Some(0.25));
        summary.provider_spend_unresolved = true;

        assert_eq!(exact_prior_scan_run(summary), None);
    }
}
