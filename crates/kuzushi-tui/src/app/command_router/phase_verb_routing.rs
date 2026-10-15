//! Direct phase verbs (`map`, `scan`, `review`, `prove`, `fix`) and the
//! explicit `plan <phase>` planner verb.
//!
//! A phase the engagement has completed or passed is something to look at, so
//! its verb opens the durable Workbench page (exactly as Shift+Tab reaches
//! it). A phase the journey has not reached yet is work to start, so its verb
//! keeps opening the planner. An unresolved result opens its review page before
//! more work is proposed. `plan <phase>` always opens the planner.

use super::*;
use crate::app::{WorkbenchPage, WorkflowPhase};

impl ShellApp {
    /// True when the journey has completed or passed `phase`, derived from the
    /// same cached reality projection that drives the phase rail.
    pub(crate) fn phase_verb_opens_page(&self, phase: WorkflowPhase) -> bool {
        crate::ui_view_models::phase_verb_opens_page(self, phase)
    }

    pub(crate) fn reduce_phase_verb(&mut self, phase: WorkflowPhase) -> Vec<ShellEffect> {
        if !self.phase_verb_opens_page(phase) {
            return self.reduce_phase_planner(phase);
        }
        self.set_workbench_page(WorkbenchPage::from_phase(phase));
        Vec::new()
    }

    pub(crate) fn reduce_phase_planner(&mut self, phase: WorkflowPhase) -> Vec<ShellEffect> {
        self.open_requested_phase_picker(phase);
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::ShellView;
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    #[test]
    fn phase_verbs_open_pending_results_without_deciding_or_starting_work() {
        for phase in WorkflowPhase::INVESTIGATION_ORDER.iter().copied() {
            for outcome in [
                PhaseAttemptOutcome::Completed,
                PhaseAttemptOutcome::Partial,
                PhaseAttemptOutcome::Failed,
                PhaseAttemptOutcome::Canceled,
            ] {
                let root = tempfile::tempdir().unwrap();
                let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
                app.set_target(Some(root.path().to_path_buf()));
                crate::test_support::record_indexed_run(
                    root.path(),
                    "pending-metadata",
                    match phase {
                        WorkflowPhase::Map => "threat-model:import",
                        WorkflowPhase::Scan => "sast:scan",
                        WorkflowPhase::Review => "triage:run",
                        _ => unreachable!("investigation phases only"),
                    },
                    serde_json::json!({"ok":true,"data":{}}),
                );
                crate::test_support::append_typed_attempt(
                    root.path(),
                    phase,
                    "pending-metadata",
                    outcome,
                );
                app.refresh_phase_attempt_projection();
                app.set_shell_view(ShellView::Logs);
                assert!(app.reduce_phase_verb(phase).is_empty());
                assert_eq!(
                    app.shell_view(),
                    ShellView::Workbench,
                    "{phase:?} {outcome:?}"
                );
                assert_eq!(
                    app.router.workbench().page(),
                    Some(WorkbenchPage::from_phase(phase))
                );
                assert!(app.engagement.unresolved_phase_attempt(phase).is_some());
                assert!(!app.has_running_work());
            }
        }
    }

    #[test]
    fn an_explicit_planner_command_still_opens_work_selection_for_a_pending_result() {
        let root = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(root.path().to_path_buf()));
        crate::test_support::record_indexed_run(
            root.path(),
            "pending-map",
            "threat-model:import",
            serde_json::json!({"ok":true,"data":{}}),
        );
        crate::test_support::append_typed_attempt(
            root.path(),
            WorkflowPhase::Map,
            "pending-map",
            PhaseAttemptOutcome::Completed,
        );
        app.refresh_phase_attempt_projection();
        assert!(app.reduce_phase_planner(WorkflowPhase::Map).is_empty());
        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Map)
            .is_some());
        assert!(!app.has_running_work());
    }
}
