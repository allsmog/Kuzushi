use super::*;
use kuzushi_core::run_lifecycle::{PhaseReceiptProjection, WorkflowContinuation};

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
            Self::Invalid { .. } => selection_blocked_result_policy(
                "run receipt unavailable; open the failed run, run it again, or discard it",
            ),
        }
    }

    pub(super) fn outcome(&self) -> PhaseAttemptOutcome {
        match self {
            Self::Ready(receipt) => phase_attempt_outcome_from_run_status(receipt.status),
            Self::Invalid {
                fallback_outcome, ..
            } => *fallback_outcome,
        }
    }

    pub(super) fn detail_lines(&self) -> Option<Vec<String>> {
        match self {
            Self::Ready(receipt) => Some(receipt_detail_lines(receipt)),
            Self::Invalid { reason, .. } => Some(vec![format!(
                "run receipt unavailable — {}; open the failed run for details",
                operator_receipt_issue(reason)
            )]),
        }
    }

    fn invalid(completed: &PhaseAttemptCompleted, reason: String) -> Self {
        Self::Invalid {
            reason,
            fallback_outcome: completed.outcome,
        }
    }
}

fn operator_receipt_issue(reason: &str) -> &'static str {
    if reason == "attempt identity is not typed" {
        return "this attempt uses legacy metadata";
    }
    if reason == "phase attempt has no run reference" {
        return "this attempt has no run reference";
    }
    if reason == "typed run has no hash-linked workflow-v2 receipt" {
        return "the run has no durable workflow receipt";
    }
    "the referenced run could not be inspected"
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
    let outcome = phase_attempt_outcome_from_run_status(receipt.status);
    let mut actions = phase_actions(&receipt.offered_actions);
    add_local_result_controls(&mut actions, outcome);
    PhaseResultPolicy {
        actions,
        recommended_next: Some(receipt.continuation.operator_label()),
    }
}

/// A typed receipt owns workflow continuations, but discarding an unresolved
/// failed result is a local attempt-disposition control: it records that the
/// operator rejected this attempt without deleting the canonical run evidence.
/// Keep that control in the TUI policy instead of inventing a core workflow
/// continuation solely to expose the existing `d` action.
fn add_local_result_controls(actions: &mut Vec<PhaseResultAction>, outcome: PhaseAttemptOutcome) {
    if matches!(
        outcome,
        PhaseAttemptOutcome::Blocked | PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled
    ) && !actions.contains(&PhaseResultAction::Discard)
    {
        actions.push(PhaseResultAction::Discard);
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

fn receipt_detail_lines(receipt: &PhaseReceiptProjection) -> Vec<String> {
    // The continuation is NOT repeated here: the card's trailing `next:` row
    // already carries `receipt.continuation` via the receipt policy.
    vec![format!(
        "receipt · {} · {} run(s) · {} · {} · {} artifact links · {} interaction(s)",
        receipt.status.label(),
        receipt.run_ids.len(),
        kuzushi_core::run_lifecycle::cost_label(receipt.cost),
        typed_finding_delta_label(&receipt.finding_delta),
        receipt.artifact_ids.len(),
        receipt.interaction_count,
    )]
}

fn typed_finding_delta_label(delta: &kuzushi_core::run_lifecycle::FindingDeltaSummary) -> String {
    let total = delta
        .added
        .saturating_add(delta.updated)
        .saturating_add(delta.removed);
    super::finding_delta_label(
        &format!("+{} ~{} -{}", delta.added, delta.updated, delta.removed),
        total,
        Some(delta.is_fully_observed()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_terminal_receipts_keep_the_local_discard_control() {
        for outcome in [
            PhaseAttemptOutcome::Blocked,
            PhaseAttemptOutcome::Failed,
            PhaseAttemptOutcome::Canceled,
        ] {
            let mut actions = vec![PhaseResultAction::Open, PhaseResultAction::RunAgain];
            add_local_result_controls(&mut actions, outcome);
            assert_eq!(
                actions,
                vec![
                    PhaseResultAction::Open,
                    PhaseResultAction::RunAgain,
                    PhaseResultAction::Discard,
                ],
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn typed_detail_line_says_unmeasured_when_no_run_committed_a_delta() {
        let delta = |watermark: &str| kuzushi_core::run_lifecycle::FindingDeltaSummary {
            added: 0,
            updated: 0,
            removed: 0,
            store_watermark: kuzushi_core::run_lifecycle::SafeText::operator_visible(watermark),
            finding_id_samples: Vec::new(),
        };

        assert_eq!(
            typed_finding_delta_label(&delta("unavailable:no typed finding commit")),
            "findings unmeasured"
        );
        assert_eq!(typed_finding_delta_label(&delta("12")), "findings +0 ~0 -0");
    }

    #[test]
    fn successful_and_partial_receipts_do_not_gain_a_new_discard_policy() {
        for outcome in [PhaseAttemptOutcome::Completed, PhaseAttemptOutcome::Partial] {
            let mut actions = vec![PhaseResultAction::Open];
            add_local_result_controls(&mut actions, outcome);
            assert_eq!(actions, vec![PhaseResultAction::Open], "{outcome:?}");
        }
    }

    #[test]
    fn local_discard_control_is_idempotent() {
        let mut actions = vec![PhaseResultAction::Open, PhaseResultAction::Discard];
        add_local_result_controls(&mut actions, PhaseAttemptOutcome::Failed);
        assert_eq!(
            actions,
            vec![PhaseResultAction::Open, PhaseResultAction::Discard]
        );
    }
}
