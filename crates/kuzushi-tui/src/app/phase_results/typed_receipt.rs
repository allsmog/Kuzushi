use super::*;
use kuzushi_core::run_lifecycle::{PhaseReceiptProjection, RunItemStatus, WorkflowContinuation};

#[derive(Debug, Clone)]
pub(super) enum TypedReceiptResolution {
    Ready(PhaseReceiptProjection),
    Invalid {
        reason: String,
        fallback_outcome: PhaseAttemptOutcome,
    },
}

impl TypedReceiptResolution {
    pub(super) fn resolve(completed: &PhaseAttemptCompleted) -> Self {
        let target = std::path::Path::new(&completed.target_snapshot.target);
        match kuzushi_core::workflow_attempts::load_phase_receipt_projection_v2(
            target,
            &completed.attempt_id,
        ) {
            Ok(Some(receipt)) => Self::Ready(receipt),
            Err(error) => Self::invalid(completed, error.to_string()),
            Ok(None) => classify_missing_receipt(target, completed),
        }
    }

    pub(super) fn authoritative_policy(&self) -> PhaseResultPolicy {
        match self {
            Self::Ready(receipt) => receipt_policy(receipt),
            Self::Invalid { reason, .. } => selection_blocked_result_policy(&format!(
                "typed phase receipt is degraded: {reason}"
            )),
        }
    }

    pub(super) fn outcome(&self) -> PhaseAttemptOutcome {
        match self {
            Self::Ready(receipt) => phase_outcome(receipt.status),
            Self::Invalid {
                fallback_outcome, ..
            } => *fallback_outcome,
        }
    }

    pub(super) fn detail_lines(&self) -> Option<Vec<String>> {
        match self {
            Self::Ready(receipt) => Some(receipt_detail_lines(receipt)),
            Self::Invalid { reason, .. } => {
                Some(vec![format!("typed phase receipt degraded — {reason}")])
            }
        }
    }

    fn invalid(completed: &PhaseAttemptCompleted, reason: String) -> Self {
        Self::Invalid {
            reason,
            fallback_outcome: completed.outcome,
        }
    }
}

fn classify_missing_receipt(
    target: &std::path::Path,
    completed: &PhaseAttemptCompleted,
) -> TypedReceiptResolution {
    if kuzushi_core::run_lifecycle::RunAttemptId::parse(&completed.attempt_id).is_err() {
        return TypedReceiptResolution::invalid(
            completed,
            "attempt identity is not typed".to_string(),
        );
    }
    let Some(final_run) = completed.run_refs.last() else {
        return TypedReceiptResolution::invalid(
            completed,
            "phase attempt has no run reference".to_string(),
        );
    };
    match kuzushi_core::run_lifecycle::load_run_projection(target, final_run) {
        Ok(_) => TypedReceiptResolution::invalid(
            completed,
            "typed run has no hash-linked workflow-v2 receipt".to_string(),
        ),
        Err(error) => TypedReceiptResolution::invalid(
            completed,
            format!("referenced run could not be inspected: {error}"),
        ),
    }
}

fn receipt_policy(receipt: &PhaseReceiptProjection) -> PhaseResultPolicy {
    PhaseResultPolicy {
        actions: phase_actions(&receipt.offered_actions),
        recommended_next: Some(receipt.continuation.operator_label()),
    }
}

fn phase_actions(continuations: &[WorkflowContinuation]) -> Vec<PhaseResultAction> {
    let mut actions = Vec::new();
    for continuation in continuations {
        let action = phase_action(continuation);
        if !actions.contains(&action) {
            actions.push(action);
        }
    }
    actions
}

fn phase_action(continuation: &WorkflowContinuation) -> PhaseResultAction {
    match continuation {
        WorkflowContinuation::OpenPhase { .. } => PhaseResultAction::SelectAndContinue,
        WorkflowContinuation::OpenReport { .. } => PhaseResultAction::SelectAndReport,
        WorkflowContinuation::InspectRun { .. } | WorkflowContinuation::AwaitDecision { .. } => {
            PhaseResultAction::Open
        }
        WorkflowContinuation::Retry { .. } => PhaseResultAction::RunAgain,
        WorkflowContinuation::NoFurtherAction { .. } => PhaseResultAction::Select,
    }
}

fn phase_outcome(status: RunItemStatus) -> PhaseAttemptOutcome {
    match status {
        RunItemStatus::Completed | RunItemStatus::Skipped => PhaseAttemptOutcome::Completed,
        RunItemStatus::Partial => PhaseAttemptOutcome::Partial,
        RunItemStatus::Canceled => PhaseAttemptOutcome::Canceled,
        RunItemStatus::Blocked | RunItemStatus::Failed | RunItemStatus::Interrupted => {
            PhaseAttemptOutcome::Failed
        }
        RunItemStatus::Pending | RunItemStatus::Running => PhaseAttemptOutcome::Partial,
    }
}

fn receipt_detail_lines(receipt: &PhaseReceiptProjection) -> Vec<String> {
    // The continuation is NOT repeated here: the card's trailing `next:` row
    // already carries `receipt.continuation` via the receipt policy.
    let delta = &receipt.finding_delta;
    vec![format!(
        "receipt · {} · {} run(s) · {} · findings +{} ~{} -{} · {} artifact(s) · {} interaction(s)",
        receipt.status.label(),
        receipt.run_ids.len(),
        kuzushi_core::run_lifecycle::cost_label(receipt.cost),
        delta.added,
        delta.updated,
        delta.removed,
        receipt.artifact_ids.len(),
        receipt.interaction_count,
    )]
}
