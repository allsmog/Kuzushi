//! Bounded background ledger reads with request-owned presentation continuations.
use super::*;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(crate) struct FindingsRefreshState {
    next_id: u64,
    pending: Option<PendingFindingsRefresh>,
    failed_target: Option<PathBuf>,
    waiting_target: Option<PathBuf>,
    // Retain a wait across retries until a projection or failure settles it.
    receipt_recovery_target: Option<PathBuf>,
}

struct PendingFindingsRefresh {
    target: PathBuf,
    request: FindingsReadRequest,
    prior_filter: Option<String>,
    prior_watermark: Option<u64>,
    interaction: Option<Instant>,
    origin: ShellView,
    announce: bool,
    scheduled: bool,
    continuation: Vec<ShellEffect>,
}

impl std::fmt::Debug for FindingsRefreshState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FindingsRefreshState")
            .field("next_id", &self.next_id)
            .field(
                "pending",
                &self.pending.as_ref().map(|pending| &pending.request),
            )
            .field("failed_target", &self.failed_target)
            .field("waiting_target", &self.waiting_target)
            .field("receipt_recovery_target", &self.receipt_recovery_target)
            .finish()
    }
}

impl FindingsRefreshState {
    pub(crate) fn accept_projection(&mut self) {
        self.pending = None;
        self.failed_target = None;
        self.waiting_target = None;
        self.receipt_recovery_target = None;
    }
    pub(crate) fn invalidate_scheduling(&mut self) {
        if let Some(pending) = &mut self.pending {
            pending.scheduled = false;
        }
    }
}

impl ShellApp {
    pub(crate) fn findings_read_precedes_history(&self) -> bool {
        self.runtime_state
            .findings_refresh
            .pending
            .as_ref()
            .is_some_and(|pending| self.target() == Some(pending.target.as_path()))
            && !self.waiting_for_findings_receipt()
    }

    pub(crate) fn can_defer_findings_refresh(&self, remaining: &VecDeque<ShellEffect>) -> bool {
        self.runtime_state.has_terminal_loop()
            && self.target().is_some()
            && remaining.iter().all(is_refresh_presentation_effect)
    }

    pub(crate) fn defer_findings_refresh(
        &mut self,
        refresh: FindingsRefresh,
        continuation: Vec<ShellEffect>,
    ) {
        // A findings read is target-scoped, so a deferral without one has
        // nothing to read — and nothing to report as failed either, which is
        // why this does not record a read failure. `restore_linked_findings`
        // defers without the `can_defer_findings_refresh` guard, so this is
        // reachable; only an operator-initiated refresh is worth naming.
        let Some(target) = self.target_owned() else {
            if refresh.announce {
                self.log_refresh_findings_error(
                    anyhow::anyhow!("No target is active. Open a target, then refresh findings."),
                    true,
                );
            }
            return;
        };
        if refresh.announce {
            self.reset_findings_page_request();
        }
        let operator = match self.identity_policy_operator_state_dir() {
            Ok(operator) => operator,
            Err(error) => {
                self.log_refresh_findings_error(error, true);
                return;
            }
        };
        let carried = self.take_passive_findings_refresh(&refresh, &continuation);
        self.runtime_state.findings_refresh.next_id =
            self.runtime_state.findings_refresh.next_id.wrapping_add(1);
        let id = self.runtime_state.findings_refresh.next_id;
        let pending =
            self.pending_findings_refresh(id, target, operator, refresh, continuation, carried);
        self.runtime_state.findings_refresh.pending = Some(pending);
        self.runtime_state.requested_findings_page = None;
        self.runtime_state.findings_refresh.failed_target = None;
        self.runtime_state.findings_refresh.waiting_target = None;
        self.schedule_pending_findings_refresh();
    }

    fn take_passive_findings_refresh(
        &mut self,
        refresh: &FindingsRefresh,
        continuation: &[ShellEffect],
    ) -> Option<PendingFindingsRefresh> {
        if self.runtime_state.requested_findings_page.is_some() {
            return None;
        }
        if !self.is_passive_findings_refresh(refresh, continuation) {
            return None;
        }
        let pending = self.runtime_state.findings_refresh.pending.as_ref()?;
        if self.target() != Some(pending.target.as_path()) {
            return None;
        }
        self.runtime_state.findings_refresh.pending.take()
    }

    fn is_passive_findings_refresh(
        &self,
        refresh: &FindingsRefresh,
        continuation: &[ShellEffect],
    ) -> bool {
        !refresh.announce
            && continuation.is_empty()
            && refresh
                .filter
                .as_ref()
                .or(self.active_findings_filter().as_ref())
                == self.active_findings_filter().as_ref()
    }

    pub(crate) fn clear_failed_findings_refresh_notice(&mut self) {
        let owned_error = self.advisory().notice.as_ref().is_some_and(|notice| {
            notice.source == "findings" && notice.message.starts_with("Ledger refresh failed:")
        });
        if owned_error {
            self.clear_notice();
        }
    }

    fn pending_findings_refresh(
        &self,
        id: u64,
        target: PathBuf,
        operator: PathBuf,
        refresh: FindingsRefresh,
        continuation: Vec<ShellEffect>,
        carried: Option<PendingFindingsRefresh>,
    ) -> PendingFindingsRefresh {
        let filter = carried
            .as_ref()
            .map(|pending| pending.request.filter.clone())
            .unwrap_or_else(|| {
                refresh
                    .filter
                    .or_else(|| self.active_findings_filter().clone())
            });
        let pending = PendingFindingsRefresh {
            target,
            request: self.findings_read_request(id, operator, filter),
            prior_filter: self.active_findings_filter().clone(),
            prior_watermark: self.findings_read_watermark(),
            interaction: self.ui().operator_interaction_stamp(),
            origin: self.shell_view(),
            announce: refresh.announce,
            scheduled: false,
            continuation,
        };
        match carried {
            Some(carried) => PendingFindingsRefresh {
                request: FindingsReadRequest {
                    page: carried.request.page,
                    recover_missing_anchor: carried.request.recover_missing_anchor,
                    ..pending.request
                },
                interaction: carried.interaction,
                origin: carried.origin,
                announce: carried.announce,
                continuation: carried.continuation,
                ..pending
            },
            None => pending,
        }
    }

    pub(crate) fn schedule_pending_findings_refresh(&mut self) -> bool {
        let Some(pending) = &self.runtime_state.findings_refresh.pending else {
            return false;
        };
        if self.target() != Some(pending.target.as_path()) {
            self.runtime_state.findings_refresh.pending = None;
            return false;
        }
        if pending.scheduled || self.waiting_for_findings_receipt() {
            return false;
        }
        let target = pending.target.clone();
        let key = ViewHydrationKey::FindingsProjection(pending.request.clone());
        let scheduled = !self
            .runtime_state
            .schedule_view_hydration(target, vec![key])
            .is_empty();
        if let Some(pending) = self.runtime_state.findings_refresh.pending.as_mut() {
            pending.scheduled = scheduled;
        }
        scheduled
    }

    pub(crate) fn findings_refresh_status(&self) -> Option<String> {
        self.findings_read_feedback()
            .map(|feedback| feedback.message)
    }

    pub(crate) fn findings_read_feedback(
        &self,
    ) -> Option<crate::ui_view_models::ReviewReadFeedback> {
        use crate::ui_view_models::ReviewReadFeedback;
        let state = &self.runtime_state.findings_refresh;
        let study = self.router.campaign().active_batch_id.is_some();
        if self.waiting_for_findings_receipt() {
            return Some(ReviewReadFeedback::waiting(study));
        }
        if let Some(pending) = &state.pending {
            return Some(ReviewReadFeedback::loading(
                study,
                pending.request.filter.as_deref(),
            ));
        }
        state
            .failed_target
            .as_deref()
            .is_some_and(|target| self.target() == Some(target))
            .then(|| ReviewReadFeedback::failed(study))
    }

    pub(crate) fn apply_findings_projection_drain(
        &mut self,
        drain: ViewHydrationDrain,
    ) -> ViewHydrationDrain {
        let mut remaining = ViewHydrationDrain::default();
        for result in drain.results {
            match (result.key, result.value) {
                (
                    ViewHydrationKey::FindingsProjection(request),
                    ViewHydrationValue::FindingsProjection(value),
                ) => {
                    self.finish_findings_refresh(&result.target, &request, value);
                }
                (key, value) => remaining.results.push(ViewHydrationResult {
                    target: result.target,
                    key,
                    value,
                }),
            }
        }
        for failure in drain.failures {
            if let ViewHydrationKey::FindingsProjection(request) = &failure.key {
                self.finish_findings_refresh(
                    &failure.target,
                    request,
                    Err("Ledger reader stopped; retry findings refresh".into()),
                );
            } else {
                remaining.failures.push(failure);
            }
        }
        self.schedule_pending_findings_refresh();
        remaining
    }

    fn finish_findings_refresh(
        &mut self,
        target: &Path,
        request: &FindingsReadRequest,
        value: Result<FindingsReadSnapshot, FindingsReadFailure>,
    ) {
        let Some(pending) = self.runtime_state.findings_refresh.pending.take() else {
            return;
        };
        if pending.request != *request || pending.target != target {
            self.runtime_state.findings_refresh.pending = Some(pending);
            return;
        }
        if !self.findings_refresh_request_is_current(&pending) {
            return;
        }
        self.finish_current_findings_read(pending, request, value);
    }

    fn finish_current_findings_read(
        &mut self,
        mut pending: PendingFindingsRefresh,
        request: &FindingsReadRequest,
        value: Result<FindingsReadSnapshot, FindingsReadFailure>,
    ) {
        match value {
            Ok(snapshot) => {
                self.apply_findings_read_snapshot(snapshot, request, pending.announce);
                self.resume_findings_refresh_presentation(pending);
            }
            Err(FindingsReadFailure::ReceiptPending) => {
                pending.scheduled = false;
                self.record_pending_findings_receipt();
                self.runtime_state.findings_refresh.pending = Some(pending);
            }
            Err(FindingsReadFailure::Failed(error)) => self.fail_findings_refresh(request, error),
        }
    }

    fn waiting_for_findings_receipt(&self) -> bool {
        self.runtime_state
            .findings_refresh
            .waiting_target
            .as_deref()
            .is_some_and(|target| self.target() == Some(target))
    }

    pub(crate) fn accept_findings_projection(&mut self, target: &Path) {
        let recovered = self
            .runtime_state
            .findings_refresh
            .receipt_recovery_target
            .as_deref()
            == Some(target)
            && self.target() == Some(target);
        self.runtime_state.findings_refresh.accept_projection();
        if recovered {
            self.log("note", "Findings refreshed; receipt wait cleared");
        }
    }

    pub(crate) fn record_pending_findings_receipt(&mut self) {
        if self.waiting_for_findings_receipt() {
            return;
        }
        self.runtime_state.findings_refresh.waiting_target = self.target_owned();
        self.runtime_state.findings_refresh.receipt_recovery_target = self.target_owned();
        self.runtime_state.findings_refresh.failed_target = None;
        self.invalidate_findings_review_completion();
        self.log(
            "note",
            "Work receipts pending; previous findings retained. Retry: findings refresh",
        );
    }

    fn fail_findings_refresh(&mut self, request: &FindingsReadRequest, error: String) {
        self.record_findings_read_failure();
        if failed_refresh_requires_qualification_reset(request) {
            self.invalidate_findings_review_completion();
        }
        self.set_error_notice(
            "findings",
            with_next_step(
                format!("Ledger refresh failed: {error}"),
                "findings refresh",
            ),
        );
    }

    pub(crate) fn record_findings_read_failure(&mut self) {
        self.runtime_state.findings_refresh.waiting_target = None;
        self.runtime_state.findings_refresh.receipt_recovery_target = None;
        self.runtime_state.findings_refresh.failed_target = self.target_path_buf().cloned();
        let deck = self.router.campaign_mut();
        if deck.active_batch_id.is_some() {
            deck.active_batch_report = None;
            deck.active_batch_observation_fingerprints.clear();
        }
    }

    fn findings_refresh_request_is_current(&self, pending: &PendingFindingsRefresh) -> bool {
        self.findings_refresh_projection_is_current(pending)
            && self.active_findings_filter() == &pending.prior_filter
            && self.current_findings_request_context(pending) == pending.request
    }

    fn current_findings_request_context(
        &self,
        pending: &PendingFindingsRefresh,
    ) -> FindingsReadRequest {
        let mut current = self.findings_read_request(
            pending.request.id,
            pending.request.operator_state.clone(),
            pending.request.filter.clone(),
        );
        current.page = pending.request.page.clone();
        current.recover_missing_anchor = pending.request.recover_missing_anchor;
        current
    }

    fn findings_refresh_projection_is_current(&self, pending: &PendingFindingsRefresh) -> bool {
        self.target() == Some(pending.target.as_path())
            && self.findings_read_watermark() == pending.prior_watermark
    }

    fn resume_findings_refresh_presentation(&mut self, pending: PendingFindingsRefresh) {
        let interaction_unchanged = self.ui().operator_interaction_stamp() == pending.interaction
            && self.shell_view() == pending.origin;
        let mut continuation = pending
            .continuation
            .into_iter()
            .filter(|effect| interaction_unchanged || !is_refresh_navigation_effect(effect))
            .collect::<Vec<_>>();
        continuation.extend(self.review_yield_queue_scoring_effects());
        EffectRuntime::execute(self, continuation);
    }
}

fn is_refresh_presentation_effect(effect: &ShellEffect) -> bool {
    is_refresh_navigation_effect(effect)
        || matches!(
            effect,
            ShellEffect::ReportFilteredFindingMovement(_) | ShellEffect::HydrateSceneSnapshots(_)
        )
}

fn failed_refresh_requires_qualification_reset(request: &FindingsReadRequest) -> bool {
    request
        .filter
        .as_deref()
        .is_none_or(|filter| FindingListFilter::from_filter_expression(filter).is_ok())
}

fn is_refresh_navigation_effect(effect: &ShellEffect) -> bool {
    matches!(
        effect,
        ShellEffect::OpenFinding(_)
            | ShellEffect::FinalizeOpenFinding(_)
            | ShellEffect::FinalizeWorkbenchOpen(_)
    )
}
