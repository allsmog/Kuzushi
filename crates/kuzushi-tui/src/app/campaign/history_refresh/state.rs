//! Immutable read inputs and the single latest presentation request.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CampaignHistoryReadRequest {
    pub(crate) id: u64,
    pub(crate) preferred: Option<String>,
    pub(crate) decisions: CampaignDecisionCounts,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CampaignDecisionCounts {
    decided: usize,
    rejected: usize,
    confirmed: usize,
    unreadable: bool,
}

impl CampaignDecisionCounts {
    pub(super) fn capture(app: &ShellApp) -> Self {
        let metrics = app.domain().review_trend().unwrap_or_default();
        Self {
            decided: metrics.decided_findings,
            rejected: metrics.rejected_false_positives,
            confirmed: metrics.confirmed_findings,
            unreadable: app.domain().review_trend().is_none() || metrics.decisions_unreadable,
        }
    }

    pub(crate) fn metrics(&self) -> kuzushi_core::capabilities::campaign::trend::TrendMetrics {
        kuzushi_core::capabilities::campaign::trend::TrendMetrics {
            decided_findings: self.decided,
            rejected_false_positives: self.rejected,
            confirmed_findings: self.confirmed,
            decisions_unreadable: self.unreadable,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CampaignHistoryReadSnapshot {
    pub(crate) history: CampaignHistory,
    pub(crate) phase: Option<CampaignPhaseRead>,
    pub(crate) trend_history:
        Vec<kuzushi_core::capabilities::campaign::trend_history::TrendSnapshot>,
}

#[derive(Clone, Debug)]
pub(crate) struct CampaignPhaseRead {
    pub(crate) snapshot: kuzushi_core::workflow_attempts::PhaseTargetSnapshot,
    pub(crate) recovered:
        Result<kuzushi_core::workflow_attempts::RecoveredPhaseAttemptLedger, String>,
}

#[derive(Debug, Default)]
pub(crate) struct CampaignHistoryRefreshState {
    pub(super) next_id: u64,
    pub(super) pending: Option<PendingHistoryRead>,
    pub(super) failed_target: Option<PathBuf>,
}

#[derive(Debug)]
pub(super) struct PendingHistoryRead {
    pub(super) target: PathBuf,
    pub(super) request: CampaignHistoryReadRequest,
    pub(super) scheduled: bool,
    pub(super) select_requested: Option<String>,
    pub(super) batch_results: bool,
    pub(super) prior_notice: Option<String>,
    pub(super) phase_generation: u64,
}

impl CampaignHistoryRefreshState {
    pub(crate) fn invalidate_scheduling(&mut self) {
        if let Some(pending) = &mut self.pending {
            pending.scheduled = false;
        }
    }
}
