use crate::run_lifecycle::{
    FindingDeltaSummary, ProjectionHealth, RunId, RunItemId, RunItemStatus, RunItemV1,
    RunProjection, SafeText, WorkflowContinuation, MAX_ARTIFACT_REFERENCES, MAX_FINDING_ID_SAMPLES,
};
use crate::runtime::{RuntimeCost, RuntimeCostReport};
use crate::WorkflowPhase;
use anyhow::{Context, Result};

/// Pure receipt assembly over immutable, replayed run projections.
///
/// The builder deliberately has no filesystem, TUI, or current-workspace
/// access. Callers must load and validate the exact referenced runs first.
pub struct PhaseReceiptBuilder<'a> {
    phase: WorkflowPhase,
    status: RunItemStatus,
    run_ids: &'a [RunId],
    projections: &'a [RunProjection],
    selection_blocked_reason: Option<&'a str>,
}

impl<'a> PhaseReceiptBuilder<'a> {
    pub fn new(
        phase: WorkflowPhase,
        status: RunItemStatus,
        run_ids: &'a [RunId],
        projections: &'a [RunProjection],
    ) -> Self {
        Self {
            phase,
            status,
            run_ids,
            projections,
            selection_blocked_reason: None,
        }
    }

    pub fn with_selection_blocked_reason(mut self, reason: Option<&'a str>) -> Self {
        self.selection_blocked_reason = reason;
        self
    }

    pub fn build(self) -> Result<RunItemV1> {
        self.validate_inputs()?;
        let finding_delta = aggregate_finding_delta(self.projections)?;
        let continuation = self.primary_continuation(&finding_delta)?;
        Ok(RunItemV1::PhaseReceipt {
            run_ids: self.run_ids.to_vec(),
            status: self.status,
            cost: aggregate_cost(self.projections)?,
            finding_delta,
            artifact_ids: artifact_ids(self.projections),
            interaction_count: interaction_count(self.projections)?,
            offered_actions: offered_actions(
                self.final_run()?,
                &continuation,
                self.selection_is_allowed(),
                self.partial_continuation_phase(),
            ),
            continuation,
        })
    }

    fn validate_inputs(&self) -> Result<()> {
        anyhow::ensure!(
            !self.run_ids.is_empty(),
            "phase attempt has no run reference"
        );
        anyhow::ensure!(
            self.run_ids.len() == self.projections.len(),
            "phase run references and projections disagree"
        );
        for (run_id, projection) in self.run_ids.iter().zip(self.projections) {
            validate_projection(run_id, projection, self.status)?;
        }
        Ok(())
    }

    fn primary_continuation(
        &self,
        finding_delta: &FindingDeltaSummary,
    ) -> Result<WorkflowContinuation> {
        if let Some(continuation) = self.blocking_continuation()? {
            return Ok(continuation);
        }
        if let Some(continuation) = terminal_continuation(self.phase, self.projections) {
            return Ok(continuation);
        }
        Ok(default_completed_continuation(
            self.phase,
            finding_delta,
            has_finding_observation(self.projections),
        ))
    }

    fn blocking_continuation(&self) -> Result<Option<WorkflowContinuation>> {
        if let Some(question_id) = outstanding_question(self.projections) {
            return Ok(Some(WorkflowContinuation::AwaitDecision { question_id }));
        }
        if let Some(reason) = self.selection_blocked_reason {
            return Ok(Some(inspect_continuation(self.final_run()?, reason)));
        }
        if self.status != RunItemStatus::Completed {
            return Ok(Some(self.failure_continuation()?));
        }
        Ok(None)
    }

    /// A failed Map asks the operator to rebuild the context (Retry maps to
    /// the card's run-again action); other failed phases inspect with the
    /// recognized remediation drafted in. Unknown classes stay generic.
    fn failure_continuation(&self) -> Result<WorkflowContinuation> {
        let remediation = self.terminal_remediation();
        if self.phase == WorkflowPhase::Map {
            return Ok(WorkflowContinuation::Retry {
                reason: SafeText::operator_visible(map_rebuild_reason(remediation)),
            });
        }
        let reason = remediation.map_or_else(
            || "inspect the incomplete phase evidence before retrying".to_string(),
            |found| format!("{} — {}, then retry", found.cause, found.action),
        );
        Ok(inspect_continuation(self.final_run()?, &reason))
    }

    fn terminal_remediation(&self) -> Option<super::failure_remediation::FailureRemediation> {
        let terminal = self.projections.last()?.terminal.as_ref()?;
        super::failure_remediation::remediation_for(terminal.summary.as_str())
    }

    fn final_run(&self) -> Result<RunId> {
        self.run_ids
            .last()
            .cloned()
            .context("phase attempt has no run reference")
    }

    fn selection_is_allowed(&self) -> bool {
        self.selection_blocked_reason.is_none()
            && !matches!(
                self.status,
                RunItemStatus::Failed
                    | RunItemStatus::Canceled
                    | RunItemStatus::Interrupted
                    | RunItemStatus::Pending
                    | RunItemStatus::Running
            )
            && outstanding_question(self.projections).is_none()
    }

    /// A selectable partial attempt may also be accepted AND advanced from:
    /// the operator explicitly continues with partial evidence. Completed
    /// attempts already carry the continuation as their primary action.
    fn partial_continuation_phase(&self) -> Option<WorkflowPhase> {
        (self.selection_is_allowed() && self.status != RunItemStatus::Completed)
            .then(|| next_phase(self.phase))
            .flatten()
    }
}

fn validate_projection(
    run_id: &RunId,
    projection: &RunProjection,
    receipt_status: RunItemStatus,
) -> Result<()> {
    anyhow::ensure!(
        projection.health == ProjectionHealth::Healthy,
        "phase receipt cannot use a degraded run projection"
    );
    anyhow::ensure!(
        projection.run_id.as_ref() == Some(run_id),
        "phase receipt projection has the wrong run identity"
    );
    let terminal = projection
        .terminal
        .as_ref()
        .context("phase receipt run has no terminal outcome")?;
    if receipt_status == RunItemStatus::Completed {
        anyhow::ensure!(
            matches!(
                terminal.status,
                RunItemStatus::Completed | RunItemStatus::Skipped
            ),
            "completed phase receipt references a non-complete run"
        );
    }
    Ok(())
}

fn aggregate_cost(projections: &[RunProjection]) -> Result<RuntimeCostReport> {
    projections.iter().try_fold(
        RuntimeCostReport::known(RuntimeCost::ZERO),
        |total, projection| total.checked_add(projection.effective_cost(), "phase receipt cost"),
    )
}

/// Each run's LAST finding delta is its authoritative end-of-run store diff:
/// an orchestrator (e.g. `sast:scan`) emits a whole-scan diff after its inner
/// engines have emitted theirs, and summing nested deltas would double-count.
fn aggregate_finding_delta(projections: &[RunProjection]) -> Result<FindingDeltaSummary> {
    let deltas = projections
        .iter()
        .filter_map(|projection| projection.finding_deltas.last())
        .collect::<Vec<_>>();
    Ok(FindingDeltaSummary {
        added: sum_delta(&deltas, |delta| delta.added)?,
        updated: sum_delta(&deltas, |delta| delta.updated)?,
        removed: sum_delta(&deltas, |delta| delta.removed)?,
        store_watermark: deltas
            .last()
            .map_or_else(unavailable_watermark, |delta| delta.store_watermark.clone()),
        finding_id_samples: deltas
            .iter()
            .flat_map(|delta| delta.finding_id_samples.iter().cloned())
            .take(MAX_FINDING_ID_SAMPLES)
            .collect(),
    })
}

fn sum_delta(
    deltas: &[&FindingDeltaSummary],
    value: fn(&FindingDeltaSummary) -> u64,
) -> Result<u64> {
    deltas.iter().try_fold(0_u64, |total, delta| {
        total
            .checked_add(value(delta))
            .context("phase finding delta overflow")
    })
}

fn unavailable_watermark() -> SafeText {
    SafeText::operator_visible("unavailable:no typed finding commit")
}

fn artifact_ids(projections: &[RunProjection]) -> Vec<RunItemId> {
    projections
        .iter()
        .flat_map(|projection| projection.artifacts.keys().copied())
        .take(MAX_ARTIFACT_REFERENCES)
        .collect()
}

fn interaction_count(projections: &[RunProjection]) -> Result<u64> {
    projections.iter().try_fold(0_u64, |count, projection| {
        let decisions = projection
            .questions
            .values()
            .filter(|question| question.decision.is_some())
            .count() as u64;
        count
            .checked_add(decisions)
            .context("phase interaction count overflow")
    })
}

fn outstanding_question(
    projections: &[RunProjection],
) -> Option<crate::run_lifecycle::RunQuestionId> {
    projections
        .iter()
        .flat_map(|projection| projection.questions.values())
        .find(|question| question.decision.is_none())
        .map(|question| question.question_id)
}

fn terminal_continuation(
    phase: WorkflowPhase,
    projections: &[RunProjection],
) -> Option<WorkflowContinuation> {
    let continuation = projections.last()?.terminal.as_ref()?.continuation.clone();
    match continuation {
        WorkflowContinuation::NoFurtherAction { .. } if phase != WorkflowPhase::Fix => None,
        continuation => Some(continuation),
    }
}

fn default_completed_continuation(
    phase: WorkflowPhase,
    finding_delta: &FindingDeltaSummary,
    has_finding_observation: bool,
) -> WorkflowContinuation {
    if phase == WorkflowPhase::Scan
        && has_finding_observation
        && finding_delta_is_empty(finding_delta)
    {
        return WorkflowContinuation::OpenReport {
            reason: SafeText::operator_visible("the selected Scan produced no finding changes"),
        };
    }
    next_phase(phase).map_or_else(
        || WorkflowContinuation::NoFurtherAction {
            reason: SafeText::operator_visible("Fix is the terminal workflow phase"),
        },
        |phase| WorkflowContinuation::OpenPhase { phase },
    )
}

fn has_finding_observation(projections: &[RunProjection]) -> bool {
    projections
        .iter()
        .any(|projection| !projection.finding_deltas.is_empty())
}

fn finding_delta_is_empty(delta: &FindingDeltaSummary) -> bool {
    delta.added == 0 && delta.updated == 0 && delta.removed == 0
}

fn inspect_continuation(run_id: RunId, reason: &str) -> WorkflowContinuation {
    WorkflowContinuation::InspectRun {
        run_id,
        reason: SafeText::operator_visible(reason),
    }
}

fn map_rebuild_reason(
    remediation: Option<super::failure_remediation::FailureRemediation>,
) -> String {
    remediation.map_or_else(
        || "rebuild the current-revision map context after inspecting the failure evidence"
            .to_string(),
        |found| format!("rebuild the map context — {}: {} first", found.cause, found.action),
    )
}

fn offered_actions(
    final_run: RunId,
    primary: &WorkflowContinuation,
    selection_is_allowed: bool,
    partial_continuation: Option<WorkflowPhase>,
) -> Vec<WorkflowContinuation> {
    let inspect = inspect_continuation(final_run, "inspect the canonical run evidence");
    let retry = WorkflowContinuation::Retry {
        reason: SafeText::operator_visible("run the phase again with explicit operator changes"),
    };
    let mut offered = vec![primary.clone()];
    if selection_is_allowed && !matches!(primary, WorkflowContinuation::NoFurtherAction { .. }) {
        push_unique(
            &mut offered,
            WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible(
                    "select this attempt without leaving the current phase",
                ),
            },
        );
    }
    if let Some(phase) = partial_continuation {
        push_unique(&mut offered, WorkflowContinuation::OpenPhase { phase });
    }
    push_unique(&mut offered, inspect);
    if !matches!(primary, WorkflowContinuation::Retry { .. }) {
        push_unique(&mut offered, retry);
    }
    offered
}

fn push_unique(values: &mut Vec<WorkflowContinuation>, value: WorkflowContinuation) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn next_phase(phase: WorkflowPhase) -> Option<WorkflowPhase> {
    match phase {
        WorkflowPhase::Map => Some(WorkflowPhase::Scan),
        WorkflowPhase::Scan => Some(WorkflowPhase::Review),
        WorkflowPhase::Review => Some(WorkflowPhase::Prove),
        WorkflowPhase::Prove => Some(WorkflowPhase::Fix),
        WorkflowPhase::Fix => None,
    }
}

#[cfg(test)]
#[path = "receipt_builder/tests.rs"]
mod tests;
