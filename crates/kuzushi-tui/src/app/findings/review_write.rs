//! One accepted manual verdict at a time, settled through the shared ledger service.
use super::*;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

mod completion;
#[cfg(test)]
mod tests;

enum ReviewWriteFailure {
    Workspace(anyhow::Error),
    Commit(anyhow::Error),
}

type ReviewWriteResult = std::result::Result<i64, ReviewWriteFailure>;

trait ReviewDecisionWriter: std::fmt::Debug + Send + Sync {
    fn write(&self, apply: &ReviewDecisionApply) -> ReviewWriteResult;
}

#[derive(Debug)]
struct LedgerReviewDecisionWriter;

impl ReviewDecisionWriter for LedgerReviewDecisionWriter {
    fn write(&self, apply: &ReviewDecisionApply) -> ReviewWriteResult {
        let workspace =
            workspace_for_target(apply.target.as_ref()).map_err(ReviewWriteFailure::Workspace)?;
        kuzushi_core::workspace::record_user_review_decision_for_finding_with_session(
            &workspace,
            &apply.finding,
            &apply.decision,
            apply.read_watermark,
            apply.review_session_id.clone(),
        )
        .map_err(ReviewWriteFailure::Commit)
    }
}

pub(crate) struct ReviewWriteState {
    pending: Option<PendingReviewWrite>,
    writer: Arc<dyn ReviewDecisionWriter>,
}

struct PendingReviewWrite {
    apply: ReviewDecisionApply,
    context: ReviewWriteContext,
    handle: JoinHandle<ReviewWriteResult>,
}

struct ReviewWriteContext {
    origin: ShellView,
    interaction: Option<Instant>,
}

impl Default for ReviewWriteState {
    fn default() -> Self {
        Self {
            pending: None,
            writer: Arc::new(LedgerReviewDecisionWriter),
        }
    }
}

impl std::fmt::Debug for ReviewWriteState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReviewWriteState")
            .field(
                "target",
                &self.pending.as_ref().map(|pending| &pending.apply.target),
            )
            .finish()
    }
}

impl ReviewWriteState {
    pub(crate) fn start(
        &mut self,
        apply: ReviewDecisionApply,
        origin: ShellView,
        interaction: Option<Instant>,
        wake: Option<TerminalLoopWake>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.pending.is_none(),
            "A review decision is already saving"
        );
        let writer = self.writer.clone();
        let input = apply.clone();
        let handle = std::thread::Builder::new()
            .name("review-decision-write".into())
            .spawn(move || {
                let result = writer.write(&input);
                if let Some(wake) = wake {
                    wake.notify();
                }
                result
            })?;
        self.pending = Some(PendingReviewWrite {
            apply,
            context: ReviewWriteContext {
                origin,
                interaction,
            },
            handle,
        });
        Ok(())
    }

    fn take_completed(
        &mut self,
    ) -> Option<(ReviewDecisionApply, ReviewWriteContext, ReviewWriteResult)> {
        if !self.pending.as_ref()?.handle.is_finished() {
            return None;
        }
        let pending = self.pending.take()?;
        let result = pending.handle.join().unwrap_or_else(|_| {
            Err(ReviewWriteFailure::Commit(anyhow::anyhow!(
                "decision worker ended without a receipt; inspect the ledger before retrying"
            )))
        });
        Some((pending.apply, pending.context, result))
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn label(&self) -> Option<String> {
        let apply = &self.pending.as_ref()?.apply;
        Some(review_decision_finding_label(
            apply.alias.as_deref(),
            &apply.finding,
        ))
    }
}

impl Drop for ReviewWriteState {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let _ = pending.handle.join();
        }
    }
}

impl ShellApp {
    pub(crate) fn record_review_decision_effect(
        &mut self,
        apply: ReviewDecisionApply,
    ) -> Vec<ShellEffect> {
        if self.runtime_state.has_terminal_loop() {
            self.start_review_decision_write(apply);
            return Vec::new();
        }
        let result = LedgerReviewDecisionWriter.write(&apply);
        self.apply_review_write_result(apply, result, true)
    }

    fn start_review_decision_write(&mut self, apply: ReviewDecisionApply) {
        if self.refuse_pending_review_decision_write() {
            return;
        }
        self.clear_previous_review_save_notice();
        let origin = self.shell_view();
        let interaction = self.ui().operator_interaction_stamp();
        if let Err(error) =
            self.runtime_state
                .start_review_decision_write(apply, origin, interaction)
        {
            self.set_error_notice(
                "review",
                format!("Could not start the decision save: {error}"),
            );
        }
    }

    pub(crate) fn review_decision_write_pending(&self) -> bool {
        self.runtime_state.review_write.is_pending()
    }

    pub(crate) fn refuse_pending_review_decision_write(&mut self) -> bool {
        if !self.review_decision_write_pending() {
            return false;
        }
        self.set_warn_notice(
            "review",
            "A decision is saving. This request was not queued; use command history to retry.",
        );
        true
    }

    fn clear_previous_review_save_notice(&mut self) {
        let prior_receipt = self.advisory().notice.as_ref().is_some_and(|notice| {
            notice.source == "review" && notice.severity == NoticeSeverity::Success
        });
        if prior_receipt {
            self.clear_notice();
        }
    }

    pub(crate) fn review_decision_save_label(&self) -> Option<String> {
        let pending = self.runtime_state.review_write.pending.as_ref()?;
        (pending.apply.target.as_deref() == self.target())
            .then(|| self.runtime_state.review_write.label())
            .flatten()
    }
}
