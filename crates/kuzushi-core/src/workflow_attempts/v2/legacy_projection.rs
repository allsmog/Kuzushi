use super::receipt;
use crate::run_lifecycle::{
    RunId, RunItemEnvelopeV1, RunItemId, RunItemV1, WorkflowContinuation,
};
use crate::workflow_attempts::{PhaseAttemptCompleted, PhaseAttemptReceipt, PhaseResultAction};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn project_typed_receipt_to_legacy(
    target: &Path,
    completed: &mut PhaseAttemptCompleted,
    envelope: &RunItemEnvelopeV1,
) -> Result<()> {
    let existing_actions = completed
        .receipt
        .as_ref()
        .map(|receipt| receipt.actions.as_slice())
        .unwrap_or_default();
    let projection = build_legacy_projection(target, envelope, existing_actions)?;
    let receipt = completed
        .receipt
        .get_or_insert_with(empty_legacy_receipt);
    projection.apply(receipt);
    completed.bound_receipt_metadata();
    Ok(())
}

fn empty_legacy_receipt() -> PhaseAttemptReceipt {
    PhaseAttemptReceipt {
        run_count: 0,
        elapsed_secs: 0,
        cost: "cost not recorded (legacy attempt)".to_string(),
        changed_findings: 0,
        finding_delta_observed: None,
        changed_artifacts: Vec::new(),
        interaction_count: 0,
        rerun_specification: None,
        actions: Vec::new(),
        recommended_next: None,
    }
}

struct LegacyReceiptProjection {
    run_count: usize,
    cost: String,
    changed_findings: u64,
    finding_delta_observed: bool,
    changed_artifacts: Vec<String>,
    interaction_count: usize,
    actions: Vec<PhaseResultAction>,
    recommended_next: String,
}

impl LegacyReceiptProjection {
    fn apply(self, receipt: &mut PhaseAttemptReceipt) {
        receipt.run_count = self.run_count;
        receipt.cost = self.cost;
        receipt.changed_findings = self.changed_findings;
        receipt.finding_delta_observed = Some(self.finding_delta_observed);
        receipt.changed_artifacts = self.changed_artifacts;
        receipt.interaction_count = self.interaction_count;
        receipt.actions = self.actions;
        receipt.recommended_next = Some(self.recommended_next);
    }
}

fn build_legacy_projection(
    target: &Path,
    envelope: &RunItemEnvelopeV1,
    existing_actions: &[PhaseResultAction],
) -> Result<LegacyReceiptProjection> {
    let RunItemV1::PhaseReceipt {
        run_ids,
        cost,
        finding_delta,
        artifact_ids,
        interaction_count,
        offered_actions,
        continuation,
        ..
    } = &envelope.item
    else {
        anyhow::bail!("phase receipt reference does not point to a PhaseReceipt item");
    };
    Ok(LegacyReceiptProjection {
        run_count: run_ids.len(),
        cost: crate::run_lifecycle::cost_label(*cost),
        changed_findings: finding_delta_total(finding_delta)?,
        finding_delta_observed: finding_delta.is_fully_observed(),
        changed_artifacts: referenced_artifact_paths(target, run_ids, artifact_ids)?,
        interaction_count: usize::try_from(*interaction_count)
            .context("phase interaction count does not fit the compatibility receipt")?,
        actions: legacy_actions_for_continuations(offered_actions, existing_actions),
        recommended_next: continuation.operator_label(),
    })
}

fn finding_delta_total(delta: &crate::run_lifecycle::FindingDeltaSummary) -> Result<u64> {
    delta
        .added
        .checked_add(delta.updated)
        .and_then(|total| total.checked_add(delta.removed))
        .context("phase finding delta does not fit the compatibility receipt")
}

fn referenced_artifact_paths(
    target: &Path,
    run_ids: &[RunId],
    artifact_ids: &[RunItemId],
) -> Result<Vec<String>> {
    let projections = run_ids
        .iter()
        .map(|run_id| load_typed_projection(target, run_id))
        .collect::<Result<Vec<_>>>()?;
    artifact_ids
        .iter()
        .map(|artifact_id| referenced_artifact_path(&projections, *artifact_id))
        .collect()
}

fn load_typed_projection(
    target: &Path,
    run_id: &RunId,
) -> Result<crate::run_lifecycle::RunProjection> {
    let read = crate::run_lifecycle::load_run_projection(target, run_id.as_str())?;
    receipt::ensure_typed_projection(&read)?;
    Ok(read.projection)
}

fn referenced_artifact_path(
    projections: &[crate::run_lifecycle::RunProjection],
    artifact_id: RunItemId,
) -> Result<String> {
    let mut matches = projections
        .iter()
        .filter_map(|projection| projection.artifacts.get(&artifact_id));
    let artifact = matches
        .next()
        .with_context(|| format!("typed receipt artifact {artifact_id} is unavailable"))?;
    anyhow::ensure!(
        matches.next().is_none(),
        "typed receipt artifact {artifact_id} has multiple referenced owners"
    );
    Ok(artifact.path.as_str().to_string())
}

fn legacy_actions_for_continuations(
    continuations: &[WorkflowContinuation],
    existing: &[PhaseResultAction],
) -> Vec<PhaseResultAction> {
    let mut actions = continuations
        .iter()
        .map(legacy_action)
        .collect::<Vec<_>>();
    actions.extend(existing.iter().copied().filter(is_legacy_ledger_action));
    deduplicate_actions(actions)
}

fn legacy_action(continuation: &WorkflowContinuation) -> PhaseResultAction {
    match continuation {
        WorkflowContinuation::OpenPhase { .. } => PhaseResultAction::SelectAndContinue,
        WorkflowContinuation::OpenReport { .. } => PhaseResultAction::SelectAndReport,
        WorkflowContinuation::InspectRun { .. } => PhaseResultAction::Open,
        WorkflowContinuation::Retry { .. } => PhaseResultAction::RunAgain,
        WorkflowContinuation::AwaitDecision { .. } => PhaseResultAction::Open,
        WorkflowContinuation::NoFurtherAction { .. } => PhaseResultAction::Select,
    }
}

fn is_legacy_ledger_action(action: &PhaseResultAction) -> bool {
    matches!(action, PhaseResultAction::Select | PhaseResultAction::Discard)
}

fn deduplicate_actions(actions: Vec<PhaseResultAction>) -> Vec<PhaseResultAction> {
    actions.into_iter().fold(Vec::new(), |mut unique, action| {
        if !unique.contains(&action) {
            unique.push(action);
        }
        unique
    })
}
