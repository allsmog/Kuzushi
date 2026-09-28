use super::{
    phase_attempt_outcome_label, InputMode, RunFocusOrigin, RunFocusReceipt, ShellApp, ShellView,
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
        self.arm_presented_result_card();
        true
    }

    /// The card the shell just presented advertises single-key actions that
    /// only Navigate mode dispatches. Restoring the launch origin re-applies
    /// the mode the operator left behind, which for a Setup or planner launch
    /// is ordinarily Prompt — so the card arrives asking for a decision with
    /// its own keys disarmed, and the next press lands in the composer as
    /// text. Arm it here, where the destination is known.
    ///
    /// A draft in flight is operator work and is never interrupted, and an open
    /// reverse search owns every printable key from `handle_overlay_key`
    /// regardless of mode — arming over either would make the card advertise
    /// actions something else is about to consume. In both cases the mode stays
    /// as restored, and the card's control hint already names the `Esc` step
    /// that reaches the actions from there.
    fn arm_presented_result_card(&mut self) {
        if self.input().is_empty() && self.history_search().is_none() {
            self.set_input_mode(InputMode::Navigate);
        }
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
