//! Direct phase verbs (`map`, `scan`, `review`, `prove`, `fix`) and the
//! explicit `plan <phase>` planner verb.
//!
//! A phase the engagement has completed or passed is something to look at, so
//! its verb opens the durable Workbench page (exactly as Shift+Tab reaches
//! it). A phase the journey has not reached yet is work to start, so its verb
//! keeps opening the planner. `plan <phase>` always opens the planner.

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
