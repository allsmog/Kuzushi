use super::*;

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn begin_guided_scan_questions(&mut self) {
        if !self.prepare_phase_picker_state(WorkflowPhase::Map, false) {
            return;
        }
        self.engagement
            .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::MapRoute));
        self.show_guided_phase(WorkflowPhase::Map);
        self.log(
            "full",
            "full pipeline opened · answer the Map questions, then Kuzushi will hand off to Scan",
        );
    }

    pub(crate) fn guided_scan_question_is_open(&self) -> bool {
        self.shell_view() == ShellView::Workbench && self.guided_scan_question_model().is_some()
    }

    pub(crate) fn guided_scan_is_awaiting(&self, phase: WorkflowPhase) -> bool {
        self.engagement.guided_scan().is_some_and(|flow| {
            matches!(
                flow.stage(),
                GuidedScanStage::AwaitingResult {
                    phase: result_phase,
                    ..
                } if result_phase == phase
            )
        })
    }

    pub(crate) fn bind_guided_phase_result(
        &mut self,
        phase: WorkflowPhase,
        attempt_id: String,
    ) -> bool {
        if self
            .engagement
            .unresolved_phase_attempt_by_id(phase, &attempt_id)
            .is_none()
        {
            return false;
        }
        let Some(flow) = self.engagement.guided_scan_mut() else {
            return false;
        };
        if flow.stage() != GuidedScanStage::Running(phase) {
            return false;
        }
        flow.bind_result(phase, attempt_id);
        true
    }

    /// Test-only: drive the guided flow to the RESULT READY card for an
    /// already-persisted attempt, exactly as the runtime path does —
    /// Running stage, workbench routing, then result binding.
    #[cfg(test)]
    pub(crate) fn await_guided_phase_result_for_test(
        &mut self,
        phase: WorkflowPhase,
        attempt_id: String,
    ) -> bool {
        self.engagement
            .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(phase)));
        self.show_guided_phase(phase);
        self.bind_guided_phase_result(phase, attempt_id)
    }

    pub(crate) fn clear_guided_scan(&mut self) {
        self.engagement.clear_guided_scan();
        self.ui_mut().clear_phase_result_cursor();
    }

    pub(crate) fn continue_guided_scan_after_result(&mut self, phase: WorkflowPhase) -> bool {
        if !self.guided_scan_is_awaiting(phase) {
            return false;
        }
        self.ui_mut().clear_phase_result_cursor();
        if phase == WorkflowPhase::Map {
            self.continue_guided_after_map();
        } else {
            self.clear_guided_scan();
            self.open_rederived_journey_destination();
        }
        true
    }

    /// Every guided Map → Scan edge must pass through this gate. Map can be
    /// reused, skipped as an empty cached plan, or freshly completed; keeping
    /// the stop policy here prevents one route from leaking into Scan when the
    /// operator configured a Map-only engagement.
    pub(super) fn continue_guided_after_map(&mut self) {
        if self.full_pipeline_stops_after_map() {
            self.finish_guided_pipeline_at_map();
            return;
        }
        self.prepare_guided_phase(WorkflowPhase::Scan);
    }

    fn full_pipeline_stops_after_map(&self) -> bool {
        self.config().phases.stop_after == Some(kuzushi_core::GuidedPhase::Map)
    }

    fn finish_guided_pipeline_at_map(&mut self) {
        self.clear_guided_scan();
        self.engagement.set_phase(WorkflowPhase::Map);
        self.show_guided_phase(WorkflowPhase::Map);
        self.set_success_notice(
            "full",
            "full pipeline complete at Map · configured phases.stop_after=map",
        );
    }

    pub(super) fn prepare_guided_phase(&mut self, phase: WorkflowPhase) {
        if !self.prepare_phase_picker_state(phase, false) {
            self.clear_guided_scan();
            return;
        }
        self.engagement
            .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::ModuleSelection(phase)));
        self.focus_guided_module_continue();
        self.show_guided_phase(phase);
    }

    pub(super) fn show_guided_phase(&mut self, phase: WorkflowPhase) {
        self.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::from_phase(phase)));
        self.set_shell_view(ShellView::Workbench);
        self.set_input_mode(InputMode::Navigate);
    }

    pub(super) fn edit_guided_flow(&mut self, edit: impl FnOnce(&mut GuidedScanFlow)) {
        if let Some(flow) = self.engagement.guided_scan_mut() {
            edit(flow);
        }
    }

    pub(super) fn set_guided_stage(&mut self, stage: GuidedScanStage) {
        self.edit_guided_flow(|flow| flow.set_stage(stage));
    }

    pub(super) fn set_guided_error(&mut self, error: impl Into<String>) {
        self.edit_guided_flow(|flow| flow.set_error(error));
    }

    pub(super) fn set_guided_acknowledgement(&mut self, message: impl Into<String>) {
        self.edit_guided_flow(|flow| flow.set_acknowledgement(message));
    }

    pub(super) fn has_accepted_map(&self) -> bool {
        if self.engagement.phase_attempt_projection_is_degraded() {
            return false;
        }
        self.engagement
            .selected_phase_attempt(WorkflowPhase::Map)
            .is_some_and(|record| {
                self.effective_phase_attempt_blocker(&record.completed)
                    .is_none()
            })
    }

    pub(super) fn has_prior_map_artifacts(&self) -> bool {
        self.engagement
            .planning_picker()
            .tasks()
            .iter()
            .any(|row| row.artifact_state == PlanningArtifactState::Cached)
    }

    pub(super) fn mark_recommended_map_for_rebuild(&mut self) {
        for task in self.recommended_map_rerun_tasks() {
            self.engagement.planning_picker_mut().mark_rebuild(task);
        }
    }

    fn recommended_map_rerun_tasks(&self) -> Vec<PlanningTaskId> {
        let picker = self.engagement.planning_picker();
        picker
            .tasks()
            .iter()
            .filter(|row| {
                row.cli_available
                    && (picker.selected().contains(&row.id)
                        || row.artifact_state == PlanningArtifactState::Cached)
            })
            .map(|row| row.id)
            .collect()
    }

    pub(super) fn focus_guided_module_continue(&mut self) {
        let cursor = self.engagement.planning_picker().tasks().len();
        self.edit_guided_flow(|flow| flow.set_cursor(cursor));
    }

    pub(super) fn map_context_is_missing(&self) -> bool {
        self.engagement
            .planning_picker()
            .tasks()
            .iter()
            .find(|row| row.id == PlanningTaskId::GatherRepoContext)
            .is_some_and(|row| row.artifact_state != PlanningArtifactState::Cached)
    }
}
