use super::*;

#[derive(Debug, Clone)]
pub(super) struct CompletionQuarantine {
    reason: SafeText,
    inspect_action: WorkflowContinuation,
}

impl CompletionQuarantine {
    pub(super) fn for_health(run_id: Option<&RunId>, health: &RunLifecycleHealth) -> Option<Self> {
        let reason = quarantine_reason(health)?;
        Some(Self {
            reason,
            inspect_action: inspection_action(run_id),
        })
    }

    pub(super) fn status(&self, recorded: RunItemStatus) -> RunItemStatus {
        match recorded {
            RunItemStatus::Completed | RunItemStatus::Skipped => RunItemStatus::Partial,
            other => other,
        }
    }

    pub(super) fn continuation(&self) -> WorkflowContinuation {
        self.inspect_action.clone()
    }

    pub(super) fn offered_actions(&self) -> Vec<WorkflowContinuation> {
        vec![self.continuation()]
    }

    pub(super) fn qualify(
        &self,
        mut cell: RunPresentationCellV1,
        recorded: RunItemStatus,
    ) -> RunPresentationCellV1 {
        cell.disclosure = Some(RunCellDisclosureV1 {
            reason: SafeText::operator_visible(format!(
                "recorded {} status quarantined: {}",
                recorded.label(),
                self.reason
            )),
            omitted_count: None,
            inspect_action: Some(self.continuation()),
        });
        cell
    }
}

fn quarantine_reason(health: &RunLifecycleHealth) -> Option<SafeText> {
    let integrity_failed = matches!(health.integrity, ProjectionHealth::Degraded { .. });
    let durability_failed = matches!(health.durability, RunDurabilityHealth::Failed { .. });
    match (integrity_failed, durability_failed) {
        (true, true) => Some(SafeText::operator_visible(
            "stream integrity is degraded and terminal durability failed",
        )),
        (true, false) => Some(SafeText::operator_visible("stream integrity is degraded")),
        (false, true) => Some(SafeText::operator_visible("terminal durability failed")),
        (false, false) => None,
    }
}

fn inspection_action(run_id: Option<&RunId>) -> WorkflowContinuation {
    run_id.map_or_else(
        || WorkflowContinuation::NoFurtherAction {
            reason: SafeText::operator_visible(
                "inspect lifecycle health before treating this run as complete",
            ),
        },
        |run_id| WorkflowContinuation::InspectRun {
            run_id: run_id.clone(),
            reason: SafeText::operator_visible(
                "inspect the last valid durable prefix before advancing",
            ),
        },
    )
}
