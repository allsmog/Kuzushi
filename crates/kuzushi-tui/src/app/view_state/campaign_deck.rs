//! Route-local state for the Campaign deck.
//!
//! Snapshots are re-read from disk on entry and on refresh — the deck never
//! caches lifecycle truth beyond one render generation, because the
//! dispatcher (a separate process) owns `queue.json`.

use kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot;
use kuzushi_core::capabilities::campaign::trend::TrendMetrics;
use kuzushi_core::capabilities::campaign::trend_history::TrendSnapshot;
use std::collections::BTreeSet;

pub(crate) const CAMPAIGN_DEFAULT_WORKERS: usize = 2;
pub(crate) const CAMPAIGN_MAX_WORKERS: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub struct CampaignRouteState {
    pub(crate) campaigns: Vec<CampaignSnapshot>,
    pub(crate) selected_campaign: usize,
    /// List mode shows every campaign; detail mode shows the selected
    /// campaign's job matrix.
    pub(crate) detail: bool,
    pub(crate) selected_job: usize,
    /// Reading position for job details and consolidated observations.
    pub(crate) read_scroll: usize,
    /// Job ids excluded from the next Launch (per selected campaign;
    /// cleared when the campaign selection changes).
    pub(crate) excluded: BTreeSet<String>,
    pub(crate) workers: usize,
    /// Pid of the dispatcher THIS deck launched (Stop target for `K`).
    /// Dispatchers started elsewhere are visible only through queue state.
    pub(crate) dispatcher_pid: Option<u32>,
    pub(crate) dispatcher_stop_requested: bool,
    pub(crate) dispatcher_failure: Option<(std::path::PathBuf, String, String)>,
    pub(crate) notice: Option<String>,
    /// Workspace-level effectiveness trend (FP rate, cost per confirmed),
    /// refreshed with the deck and on Report entry; `None` until a target
    /// makes the fold computable.
    pub(crate) trend: Option<TrendMetrics>,
    /// Bounded trend history backing the sparkline strip; refreshed with
    /// the trend. Empty until two distinct snapshots exist.
    pub(crate) trend_history: Vec<TrendSnapshot>,
    /// Draft owned by the batch configurator. While present the Campaign
    /// surface renders configuration instead of the campaign list.
    pub(crate) setup_context_study: Option<crate::app::BatchScanConfig>,
    pub(crate) batch_scan_config: Option<crate::app::BatchScanConfig>,
    /// The batch whose occurrence report scopes Review. The id survives deck
    /// refreshes until the operator clears it or switches targets.
    pub(crate) active_batch_id: Option<String>,
    pub(crate) active_batch_report: Option<kuzushi_core::findings::BatchOccurrenceReport>,
    /// Recorded observation membership, independent of completed-pass recurrence.
    pub(crate) active_batch_observation_fingerprints: BTreeSet<String>,
}

impl Default for CampaignRouteState {
    fn default() -> Self {
        Self {
            campaigns: Vec::new(),
            selected_campaign: 0,
            detail: false,
            selected_job: 0,
            read_scroll: 0,
            excluded: BTreeSet::new(),
            workers: CAMPAIGN_DEFAULT_WORKERS,
            dispatcher_pid: None,
            dispatcher_stop_requested: false,
            dispatcher_failure: None,
            notice: None,
            trend: None,
            trend_history: Vec::new(),
            batch_scan_config: None,
            setup_context_study: None,
            active_batch_id: None,
            active_batch_report: None,
            active_batch_observation_fingerprints: BTreeSet::new(),
        }
    }
}

impl CampaignRouteState {
    pub(crate) fn has_dispatcher_failure_notice(&self) -> bool {
        self.dispatcher_failure
            .as_ref()
            .is_some_and(|(_, _, message)| self.notice.as_ref() == Some(message))
    }

    pub(crate) fn selected_campaign(&self) -> Option<&CampaignSnapshot> {
        self.campaigns.get(self.selected_campaign)
    }

    pub(crate) fn selected_job(
        &self,
    ) -> Option<&kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot> {
        self.selected_campaign()?.jobs.get(self.selected_job)
    }

    pub(crate) fn move_cursor(&mut self, delta: i64) {
        let len = if self.detail {
            self.selected_campaign().map(|c| c.jobs.len()).unwrap_or(0)
        } else {
            self.campaigns.len()
        };
        if len == 0 {
            return;
        }
        let cursor = if self.detail {
            &mut self.selected_job
        } else {
            &mut self.selected_campaign
        };
        *cursor = (*cursor as i64 + delta).clamp(0, len as i64 - 1) as usize;
        if !self.detail {
            self.selected_job = 0;
            self.read_scroll = 0;
            self.excluded.clear();
        }
    }

    pub(crate) fn included_job_ids(&self) -> Vec<String> {
        self.selected_campaign()
            .map(|campaign| {
                campaign
                    .jobs
                    .iter()
                    .map(|job| job.job_id.clone())
                    .filter(|job_id| !self.excluded.contains(job_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn toggle_selected_exclusion(&mut self) {
        let Some(job_id) = self.selected_job().map(|job| job.job_id.clone()) else {
            return;
        };
        if !self.excluded.remove(&job_id) {
            self.excluded.insert(job_id);
        }
    }

    pub(crate) fn detail_job_ceiling(&self) -> usize {
        self.selected_campaign()
            .map(|campaign| campaign.jobs.len().saturating_sub(1))
            .unwrap_or(0)
    }

    pub(crate) fn cycle_workers(&mut self) {
        self.workers = self.workers % CAMPAIGN_MAX_WORKERS + 1;
    }

    pub(crate) fn sync_selected_batch_workers(&mut self) {
        let frozen = self
            .selected_campaign()
            .filter(|campaign| crate::app::is_scan_batch_snapshot(campaign))
            .and_then(|campaign| campaign.effective_workers);
        if let Some(workers) = frozen {
            self.workers = workers;
        }
    }

    pub(crate) fn active_batch_report(
        &self,
    ) -> Option<&kuzushi_core::findings::BatchOccurrenceReport> {
        self.active_batch_report.as_ref()
    }

    pub(crate) fn clear_active_batch(&mut self) {
        self.active_batch_id = None;
        self.active_batch_report = None;
        self.active_batch_observation_fingerprints.clear();
    }
}

/// The exact dispatcher argv the deck's Launch composes — kept pure so the
/// launch contract is testable without spawning anything.
pub(crate) fn dispatcher_args(
    campaign_id: &str,
    target: &std::path::Path,
    workers: usize,
    included: &[String],
    total_jobs: usize,
) -> Vec<String> {
    let mut args = vec![
        "--target".to_string(),
        target.display().to_string(),
        "campaign".to_string(),
        "run".to_string(),
        campaign_id.to_string(),
        "--workers".to_string(),
        workers.to_string(),
    ];
    if included.len() < total_jobs {
        args.push("--jobs".to_string());
        args.push(included.join(","));
    }
    args
}

/// Scan batches launch their controller, which owns dispatch followed by the
/// exactly-once aggregate, gate, and SARIF publication sequence.
pub(crate) fn batch_controller_args(batch_id: &str, target: &std::path::Path) -> Vec<String> {
    vec![
        "--plain".to_string(),
        "--target".to_string(),
        target.display().to_string(),
        "campaign".to_string(),
        "batch".to_string(),
        batch_id.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_args_omit_jobs_when_everything_is_included() {
        let target = std::path::Path::new("/tmp/ws");
        let all = ["j1".to_string(), "j2".to_string()];
        let args = dispatcher_args("camp1", target, 3, &all, 2);
        assert_eq!(
            args,
            vec![
                "--target",
                "/tmp/ws",
                "campaign",
                "run",
                "camp1",
                "--workers",
                "3"
            ]
        );

        let subset = ["j2".to_string()];
        let args = dispatcher_args("camp1", target, 3, &subset, 2);
        assert_eq!(args[7..], ["--jobs".to_string(), "j2".to_string()]);
    }

    #[test]
    fn batch_controller_args_use_the_exact_detached_controller_contract() {
        let args = batch_controller_args("batch1", std::path::Path::new("/tmp/ws"));

        assert_eq!(
            args,
            ["--plain", "--target", "/tmp/ws", "campaign", "batch", "batch1"]
        );
        assert!(!args.iter().any(|arg| arg == "--workers" || arg == "--jobs"));
    }

    #[test]
    fn cycle_workers_wraps_within_the_dispatcher_cap() {
        let mut deck = CampaignRouteState::default();
        for _ in 0..CAMPAIGN_MAX_WORKERS {
            deck.cycle_workers();
        }
        assert_eq!(deck.workers, CAMPAIGN_DEFAULT_WORKERS);
        deck.workers = CAMPAIGN_MAX_WORKERS;
        deck.cycle_workers();
        assert_eq!(deck.workers, 1);
    }
}
