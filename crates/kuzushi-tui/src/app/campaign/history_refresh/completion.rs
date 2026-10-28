//! Apply only the latest target-owned history result.
use super::*;

impl ShellApp {
    fn campaign_history_request_is_current(
        &self,
        target: &Path,
        request: &CampaignHistoryReadRequest,
    ) -> bool {
        self.target() == Some(target)
            && self
                .runtime_state
                .campaign_history_refresh
                .pending
                .as_ref()
                .is_some_and(|pending| pending.target == target && pending.request == *request)
    }

    pub(super) fn finish_campaign_history_read(
        &mut self,
        target: &Path,
        request: &CampaignHistoryReadRequest,
        value: Option<ViewHydrationValue>,
    ) {
        if !self.campaign_history_request_is_current(target, request) {
            return;
        }
        let pending = self
            .runtime_state
            .campaign_history_refresh
            .pending
            .take()
            .unwrap();
        let Some(ViewHydrationValue::CampaignHistory(snapshot)) = value else {
            self.runtime_state.campaign_history_refresh.failed_target = Some(target.to_owned());
            self.qualify_failed_history_spending();
            return;
        };
        self.apply_ready_campaign_history(Arc::unwrap_or_clone(snapshot), pending);
    }

    fn qualify_failed_history_spending(&mut self) {
        if let Some(trend) = &mut self.router.campaign_mut().trend {
            trend.provider_spend_unresolved = true;
        }
    }

    fn apply_ready_campaign_history(
        &mut self,
        snapshot: CampaignHistoryReadSnapshot,
        pending: PendingHistoryRead,
    ) {
        let loaded_study = self
            .router
            .campaign()
            .selected_campaign()
            .filter(|_| self.router.campaign().detail)
            .map(|campaign| campaign.campaign_id.clone());
        let notice = self
            .router
            .campaign()
            .notice
            .clone()
            .filter(|notice| keep_newer_campaign_notice(notice, pending.prior_notice.as_ref()));
        let trend = CampaignDecisionCounts::capture(self)
            .metrics()
            .with_spend(snapshot.history.spend());
        self.replace_campaign_snapshots(snapshot.history);
        self.router.campaign_mut().trend = Some(trend);
        self.router.campaign_mut().trend_history = snapshot.trend_history;
        self.apply_campaign_phase_read(snapshot.phase, pending.phase_generation);
        self.finish_campaign_history_selection(&pending);
        self.reveal_new_scan_study_job(&pending, loaded_study.as_deref());
        if notice.is_some() {
            self.router.campaign_mut().notice = notice;
        }
        self.restore_dispatcher_failure_notice();
    }

    fn reveal_new_scan_study_job(&mut self, pending: &PendingHistoryRead, loaded: Option<&str>) {
        if let Some(id) = pending
            .select_requested
            .as_deref()
            .filter(|id| Some(*id) != loaded)
        {
            self.reveal_scan_study_job(id);
        }
    }

    fn apply_campaign_phase_read(&mut self, phase: Option<CampaignPhaseRead>, generation: u64) {
        if self.engagement.phase_projection_generation() != generation {
            return;
        }
        if let Some(phase) = phase {
            self.apply_loaded_phase_attempt_projection(phase.snapshot, phase.recovered);
        }
    }

    fn finish_campaign_history_selection(&mut self, pending: &PendingHistoryRead) {
        if self.shell_view() != ShellView::Campaign {
            return;
        }
        let Some(id) = &pending.select_requested else {
            return;
        };
        self.select_loaded_campaign(id);
        if pending.batch_results {
            self.finish_open_batch_results(id);
        }
    }

    fn select_loaded_campaign(&mut self, id: &str) {
        if self
            .router
            .campaign()
            .selected_campaign()
            .is_some_and(|row| row.campaign_id == id)
        {
            self.router.campaign_mut().detail = true;
            self.router.campaign_mut().sync_selected_batch_workers();
        } else {
            self.select_campaign(id);
        }
    }
}

fn keep_newer_campaign_notice(notice: &String, prior: Option<&String>) -> bool {
    Some(notice) != prior && !notice.starts_with("Wait for history to load,")
}
