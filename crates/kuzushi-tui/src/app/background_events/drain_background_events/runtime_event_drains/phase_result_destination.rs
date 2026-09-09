use super::{
    phase_attempt_outcome_label, RunFocusOrigin, RunFocusReceipt, ShellApp, ShellView,
    WorkbenchPage, WorkflowPhase,
};

impl ShellApp {
    pub(super) fn open_completed_run_destination(
        &mut self,
        origin: Option<RunFocusOrigin>,
        pending_viz: Option<crate::scene3d::VizPage>,
    ) {
        if self.present_pending_phase_result(origin) {
            return;
        }
        if let Some(page) = pending_viz {
            self.open_deferred_viz_page(page);
        }
    }

    fn present_pending_phase_result(&mut self, origin: Option<RunFocusOrigin>) -> bool {
        let Some(phase) = self.pending_result_phase(origin) else {
            return false;
        };
        self.set_workbench_page(WorkbenchPage::from_phase(phase));
        self.ui_mut().clear_phase_result_cursor();
        true
    }

    fn pending_result_phase(&self, origin: Option<RunFocusOrigin>) -> Option<WorkflowPhase> {
        let receipt = self.activity()?.run_focus_receipt.as_ref()?;
        let phase = receipt.origin_phase?;
        if !origin_presents_phase_result(origin?.view, phase, &receipt.outcome) {
            return None;
        }
        self.receipt_matches_pending_result(receipt, phase)
            .then_some(phase)
    }

    fn receipt_matches_pending_result(
        &self,
        receipt: &RunFocusReceipt,
        phase: WorkflowPhase,
    ) -> bool {
        if self.engagement.phase_attempt_projection_is_degraded() {
            return false;
        }
        let Some(attempt) = self.engagement.unresolved_phase_attempt(phase) else {
            return false;
        };
        receipt.attempt_id.as_deref() == Some(attempt.completed.attempt_id.as_str())
            && receipt.outcome == phase_attempt_outcome_label(attempt.completed.outcome)
    }
}

fn origin_presents_phase_result(view: ShellView, phase: WorkflowPhase, outcome: &str) -> bool {
    match view {
        ShellView::Setup => completed_setup_map(phase, outcome),
        ShellView::PlanningPicker => true,
        _ => false,
    }
}

fn completed_setup_map(phase: WorkflowPhase, outcome: &str) -> bool {
    phase == WorkflowPhase::Map && outcome == "completed"
}
