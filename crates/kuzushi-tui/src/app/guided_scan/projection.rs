use super::presentation_copy::*;
use super::*;
use kuzushi_core::workflow_attempts::PhaseResultAction;

impl ShellApp {
    pub(crate) fn guided_scan_question_model(&self) -> Option<GuidedScanQuestionModel> {
        if self.shell_view() != ShellView::Workbench {
            return None;
        }
        let flow = self.engagement.guided_scan()?;
        if matches!(flow.stage(), GuidedScanStage::Running(_)) {
            return None;
        }
        if let GuidedScanStage::AwaitingResult { phase, attempt_id } = flow.stage() {
            return self.phase_result_question(flow, phase, &attempt_id);
        }
        self.guided_setup_question(flow)
    }

    fn guided_setup_question(&self, flow: &GuidedScanFlow) -> Option<GuidedScanQuestionModel> {
        match flow.stage() {
            GuidedScanStage::MapRoute => Some(self.map_route_question(flow)),
            GuidedScanStage::ModuleSelection(phase) => {
                Some(self.module_selection_question(flow, phase))
            }
            GuidedScanStage::ContextPrerequisite => Some(self.context_question(flow)),
            GuidedScanStage::ConfigureOptions(phase) => self.option_question(flow, phase),
            GuidedScanStage::Running(_) | GuidedScanStage::AwaitingResult { .. } => None,
        }
    }

    fn map_route_question(&self, flow: &GuidedScanFlow) -> GuidedScanQuestionModel {
        base_question(
            flow,
            "MAP · ROUTE",
            self.map_route_prompt(),
            "Map establishes the target context Scan engines will consume.",
            map_route_options(self.has_accepted_map(), self.has_prior_map_artifacts()),
            false,
            Some(map_step_progress(1, self.map_context_is_missing())),
        )
    }

    fn map_route_prompt(&self) -> &'static str {
        if self.has_accepted_map() {
            return "Detected current Map results. What should Kuzushi do before Scan?";
        }
        if self.has_prior_map_artifacts() {
            return "Detected previous Map artifacts that are not yet an accepted current-revision attempt. What should Kuzushi re-run?";
        }
        "No accepted current-revision Map exists. What should Kuzushi map first?"
    }

    fn module_selection_question(
        &self,
        flow: &GuidedScanFlow,
        phase: WorkflowPhase,
    ) -> GuidedScanQuestionModel {
        // Scan module choices are seeded by the threat model + recommender;
        // Map builds those artifacts, so its own selection stays unseeded.
        let seed = (phase == WorkflowPhase::Scan).then(|| self.scan_seed_context());
        let picker = self.engagement.planning_picker();
        let mut options = picker
            .tasks()
            .iter()
            .map(|row| {
                module_question_option(row, picker.selected().contains(&row.id), seed.as_ref())
            })
            .collect::<Vec<_>>();
        options.push(question_option(
            &continue_module_label(
                phase,
                picker.selected().len(),
                self.map_context_is_missing(),
            ),
            "Keep this selection and advance immediately to the next required question.",
            false,
            !picker.selected().is_empty(),
        ));
        options.push(other_option());
        let mut model = base_question(
            flow,
            &format!("{} · MODULES", phase.label()),
            &format!("Which {} modules should Kuzushi run?", phase.word()),
            "Space/Enter toggles a module. Choose Continue when the set is right.",
            options,
            true,
            Some(module_selection_progress(
                phase,
                self.map_context_is_missing(),
            )),
        );
        if let Some(seed) = seed {
            model.detail_lines.push(seed.provenance);
        }
        model
    }

    fn context_question(&self, flow: &GuidedScanFlow) -> GuidedScanQuestionModel {
        base_question(
            flow,
            "MAP · PREREQUISITE",
            "We detected that repository context has not been built. Build it now?",
            "Selected Map modules consume this inventory; Kuzushi will run context:build first.",
            context_question_options(),
            false,
            Some("step 3 of 4".to_string()),
        )
    }

    fn option_question(
        &self,
        flow: &GuidedScanFlow,
        phase: WorkflowPhase,
    ) -> Option<GuidedScanQuestionModel> {
        let target = flow.current_option()?;
        let spec = self.planning_option_spec(target.task, &target.option_name)?;
        let choices = self
            .guided_option_choices()
            .into_iter()
            .map(guided_choice_option)
            .collect();
        let (current, total) = flow.option_progress();
        let mut model = base_question(
            flow,
            &format!("{} · {}", phase.label(), target.task.label()),
            &format!(
                "{} — is this setting okay?",
                humanize_option_name(&spec.name)
            ),
            &spec.description,
            choices,
            false,
            Some(option_progress(
                phase,
                current,
                total,
                self.map_context_is_missing(),
            )),
        );
        model.accept_remaining_defaults = self.can_accept_remaining_guided_defaults();
        Some(model)
    }

    fn phase_result_question(
        &self,
        flow: &GuidedScanFlow,
        phase: WorkflowPhase,
        attempt_id: &str,
    ) -> Option<GuidedScanQuestionModel> {
        let record = self
            .engagement
            .unresolved_phase_attempt_by_id(phase, attempt_id)?;
        let presentation = self.phase_result_presentation_for(&record.completed);
        let actions = presentation.actions;
        let cursor = self
            .ui()
            .phase_result_cursor_index(&record.completed.attempt_id, actions.len());
        let options = actions
            .iter()
            .enumerate()
            .map(|(index, action)| result_question_option(phase, *action, index == 0))
            .collect();
        let detail = first_detail_line(&presentation.detail_lines);
        let mut model = base_question(
            flow,
            &format!("{} · RESULT READY", phase.label()),
            &phase_result_prompt(
                phase,
                self.effective_phase_attempt_outcome(&record.completed),
                actions.contains(&PhaseResultAction::SelectAndReport),
            ),
            &detail,
            options,
            false,
            None,
        );
        model.detail_lines = presentation.detail_lines;
        model.semantic_keys = presentation.semantic_keys;
        model.cursor = cursor;
        Some(model)
    }
}

fn first_detail_line(lines: &[String]) -> String {
    lines.first().cloned().unwrap_or_default()
}

pub(super) fn module_selection_progress(phase: WorkflowPhase, map_context_missing: bool) -> String {
    if phase == WorkflowPhase::Map {
        map_step_progress(2, map_context_missing)
    } else {
        "step 1 of 2".to_string()
    }
}

pub(super) fn option_progress(
    phase: WorkflowPhase,
    current: usize,
    total: usize,
    map_context_missing: bool,
) -> String {
    let step = if phase == WorkflowPhase::Map {
        map_step_progress(4, map_context_missing)
    } else {
        "step 2 of 2".to_string()
    };
    format!("{step} · option {current} of {total}")
}

fn map_step_progress(step: usize, context_missing: bool) -> String {
    let total = if context_missing { 4 } else { 3 };
    let visible_step = if context_missing { step } else { step.min(3) };
    format!("step {visible_step} of {total}")
}

fn continue_module_label(
    phase: WorkflowPhase,
    selected: usize,
    map_context_missing: bool,
) -> String {
    let destination = match phase {
        WorkflowPhase::Map if map_context_missing => "Context check",
        WorkflowPhase::Map => "Configure Map",
        _ => "Configure Scan",
    };
    format!("Continue → {destination} ({selected} selected)")
}
