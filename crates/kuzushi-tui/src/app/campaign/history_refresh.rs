//! Request-owned history loading through the bounded view-reader pool.
use super::*;
use std::path::PathBuf;
use std::sync::Arc;

mod completion;
mod state;
use state::CampaignDecisionCounts;
use state::PendingHistoryRead;
pub(crate) use state::{
    CampaignHistoryReadRequest, CampaignHistoryReadSnapshot, CampaignHistoryRefreshState,
    CampaignPhaseRead,
};

impl ShellApp {
    pub(super) fn begin_campaign_history_refresh(
        &mut self,
        target: PathBuf,
        requested: Option<&str>,
    ) {
        self.defer_campaign_findings_read();
        let previous = self.cancel_previous_campaign_history_read();
        let select = requested
            .map(str::to_owned)
            .or_else(|| previous.as_ref()?.select_requested.clone());
        let batch_results =
            requested.is_none() && previous.is_some_and(|prior| prior.batch_results);
        let preferred = preferred_campaign(self.router.campaign(), select.as_deref());
        let decisions = CampaignDecisionCounts::capture(self);
        let notice = self.router.campaign().notice.clone();
        let phase_generation = self.engagement.phase_projection_generation();
        let state = &mut self.runtime_state.campaign_history_refresh;
        state.next_id = state.next_id.wrapping_add(1);
        state.failed_target = None;
        state.pending = Some(PendingHistoryRead {
            target,
            request: CampaignHistoryReadRequest {
                id: state.next_id,
                preferred,
                decisions,
            },
            scheduled: false,
            select_requested: select,
            batch_results,
            prior_notice: notice,
            phase_generation,
        });
        self.schedule_pending_campaign_history();
    }

    pub(crate) fn defer_campaign_findings_read(&mut self) {
        let refresh = FindingsRefresh {
            announce: false,
            filter: self.active_findings_filter().clone(),
        };
        EffectRuntime::execute(self, vec![ShellEffect::RefreshFindings(refresh)]);
    }

    fn cancel_previous_campaign_history_read(&mut self) -> Option<PendingHistoryRead> {
        let state = &mut self.runtime_state.campaign_history_refresh;
        let previous = state.pending.take();
        if let Some(pending) = &previous {
            self.runtime_state
                .cancel_single_view_read(&ViewHydrationKey::CampaignHistory(
                    pending.request.clone(),
                ));
        }
        previous
    }

    pub(crate) fn campaign_history_loading(&self) -> bool {
        self.runtime_state
            .campaign_history_refresh
            .pending
            .as_ref()
            .is_some_and(|pending| self.target() == Some(pending.target.as_path()))
    }

    pub(crate) fn pending_campaign_selection(&self) -> Option<&str> {
        if !self.campaign_history_loading() {
            return None;
        }
        let requested = self
            .runtime_state
            .campaign_history_refresh
            .pending
            .as_ref()?
            .select_requested
            .as_deref()?;
        self.router
            .campaign()
            .selected_campaign()
            .is_none_or(|current| current.campaign_id != requested)
            .then_some(requested)
    }

    pub(crate) fn campaign_history_feedback(&self) -> Option<&'static str> {
        if self.campaign_history_loading() {
            return Some("Loading history. Work controls wait; reading stays available.");
        }
        self.runtime_state
            .campaign_history_refresh
            .failed_target
            .as_deref()
            .filter(|target| self.target() == Some(*target))
            .map(|_| {
                "History refresh failed. Previous records retained; spending is unknown. r refresh."
            })
    }

    pub(super) fn cancel_campaign_history_selection(&mut self) {
        if let Some(pending) = &mut self.runtime_state.campaign_history_refresh.pending {
            pending.select_requested = None;
            pending.batch_results = false;
        }
    }

    pub(crate) fn defer_batch_results_until_history_ready(&mut self, id: &str) -> bool {
        let Some(pending) = &mut self.runtime_state.campaign_history_refresh.pending else {
            return false;
        };
        if pending.select_requested.as_deref() != Some(id) {
            return false;
        }
        pending.batch_results = true;
        true
    }

    pub(super) fn refuse_unread_campaign_action(&mut self, action: ViewHotkeyAction) -> bool {
        if self.campaign_history_feedback().is_none() || !requires_current_history(action) {
            return false;
        }
        self.router.campaign_mut().notice = Some(
            "Wait for history to load, or press r to retry. No work was started or changed.".into(),
        );
        true
    }

    pub(crate) fn schedule_pending_campaign_history(&mut self) -> bool {
        if self.findings_read_precedes_history() {
            return false;
        }
        let state = &self.runtime_state.campaign_history_refresh;
        let Some(pending) = &state.pending else {
            return false;
        };
        if self.target() != Some(pending.target.as_path()) {
            self.runtime_state.campaign_history_refresh.pending = None;
            return false;
        }
        if pending.scheduled {
            return false;
        }
        let target = pending.target.clone();
        let mut request = pending.request.clone();
        request.decisions = CampaignDecisionCounts::capture(self);
        self.runtime_state
            .campaign_history_refresh
            .pending
            .as_mut()
            .unwrap()
            .request = request.clone();
        let key = ViewHydrationKey::CampaignHistory(request);
        let scheduled = !self
            .runtime_state
            .schedule_view_hydration(target, vec![key])
            .is_empty();
        self.runtime_state
            .campaign_history_refresh
            .pending
            .as_mut()
            .unwrap()
            .scheduled = scheduled;
        scheduled
    }

    pub(crate) fn apply_campaign_history_drain(
        &mut self,
        drain: ViewHydrationDrain,
    ) -> ViewHydrationDrain {
        let mut remaining = ViewHydrationDrain::default();
        for result in drain.results {
            self.consume_campaign_history_result(result, &mut remaining);
        }
        for failure in drain.failures {
            self.consume_campaign_history_failure(failure, &mut remaining);
        }
        self.schedule_pending_campaign_history();
        remaining
    }

    fn consume_campaign_history_result(
        &mut self,
        result: ViewHydrationResult,
        remaining: &mut ViewHydrationDrain,
    ) {
        if let ViewHydrationKey::CampaignHistory(request) = result.key {
            self.finish_campaign_history_read(&result.target, &request, Some(result.value));
        } else {
            remaining.results.push(result);
        }
    }

    fn consume_campaign_history_failure(
        &mut self,
        failure: ViewHydrationFailure,
        remaining: &mut ViewHydrationDrain,
    ) {
        if let ViewHydrationKey::CampaignHistory(request) = failure.key {
            self.finish_campaign_history_read(&failure.target, &request, None);
        } else {
            remaining.failures.push(failure);
        }
    }
}

fn requires_current_history(action: ViewHotkeyAction) -> bool {
    matches!(
        action,
        ViewHotkeyAction::CampaignLaunch
            | ViewHotkeyAction::CampaignToggleExclude
            | ViewHotkeyAction::CampaignCycleWorkers
            | ViewHotkeyAction::CampaignReviewStudy
    )
}
