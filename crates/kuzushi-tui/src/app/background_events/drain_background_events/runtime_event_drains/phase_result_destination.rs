use super::{
    phase_attempt_outcome_label, InputMode, RunFocusOrigin, RunFocusReceipt, ShellApp, ShellView,
    WorkbenchPage, WorkflowPhase,
};
use crate::ui_view_models::answers_own_input;

impl ShellApp {
    pub(super) fn open_completed_run_destination(
        &mut self,
        origin: Option<RunFocusOrigin>,
        pending_viz: Option<crate::scene3d::VizPage>,
    ) {
        if self.present_context_map_result(origin) {
            return;
        }
        if self.present_pending_phase_result(origin) {
            return;
        }
        if let Some(page) = pending_viz {
            self.open_deferred_viz_page(page);
        }
    }

    fn present_context_map_result(&mut self, origin: Option<RunFocusOrigin>) -> bool {
        if !self.context_map_handoff_completed(origin) {
            return false;
        }
        self.open_reviewed_context_map()
    }

    pub(crate) fn open_reviewed_context_map(&mut self) -> bool {
        let Some(id) = self.reviewed_context_map_attempt() else {
            return false;
        };
        if !self.context_map_attempt_is_current(id) {
            return false;
        }
        self.set_workbench_page(WorkbenchPage::Map);
        self.ui_mut().clear_phase_result_cursor();
        self.arm_presented_result_card();
        true
    }

    fn context_map_handoff_completed(&self, origin: Option<RunFocusOrigin>) -> bool {
        if origin.is_none_or(|origin| origin.view != ShellView::Campaign) {
            return false;
        }
        self.activity()
            .and_then(|session| session.run_focus_receipt.as_ref())
            .and_then(|receipt| receipt.result_summaries.last())
            .is_some_and(|result| {
                result.tool == "campaign:context-map" && result.status == "completed"
            })
    }

    fn context_map_attempt_is_current(&self, id: &str) -> bool {
        if self.engagement.phase_attempt_projection_is_degraded() {
            return false;
        }
        self.engagement
            .unresolved_phase_attempt(WorkflowPhase::Map)
            .or_else(|| self.engagement.selected_phase_attempt(WorkflowPhase::Map))
            .is_some_and(|attempt| attempt.completed.attempt_id == id)
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
    /// A draft in flight is operator work and is never interrupted, whether it
    /// sits in the composer or in a Run Focus steer editor the run outlived.
    /// An open reverse search owns every printable key from
    /// `handle_overlay_key` regardless of mode, and a focused Answers deck owns
    /// them from `handle_answer_key` ahead of any card dispatch. Arming over
    /// any of these would make the card advertise actions something else is
    /// about to consume — or turn in-flight keystrokes into card decisions. In
    /// each case the mode stays as restored, and the card's control hint
    /// already names the `Esc` step that reaches the actions from there.
    fn arm_presented_result_card(&mut self) {
        if self.result_card_keys_are_unowned() {
            self.set_input_mode(InputMode::Navigate);
        }
    }

    fn result_card_keys_are_unowned(&self) -> bool {
        self.input().is_empty()
            && self.router.activity().steer_editor.is_none()
            && self.history_search().is_none()
            && !answers_own_input(self)
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
