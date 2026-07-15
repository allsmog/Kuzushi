pub(super) use super::option_choices::option_choices;
use super::presentation_copy::humanize_option_name;
use super::*;
use crate::app::state_transitions::InputUpdate;
use kuzushi_core::modules::OptionSpec;

impl ShellApp {
    pub(super) fn begin_guided_options_or_run(&mut self, phase: WorkflowPhase) -> InputUpdate {
        let targets = self.guided_option_targets();
        if targets.is_empty() {
            return self.launch_guided_phase(phase);
        }
        if let Some(flow) = self.engagement.guided_scan_mut() {
            flow.begin_options(phase, targets);
        }
        InputUpdate::handled()
    }

    pub(super) fn activate_option_choice(
        &mut self,
        phase: WorkflowPhase,
        index: usize,
    ) -> InputUpdate {
        let Some(choice) = self.guided_option_choices().get(index).cloned() else {
            return InputUpdate::handled();
        };
        match choice.value {
            GuidedOptionValue::Keep => self.advance_guided_option(phase),
            GuidedOptionValue::Set(value) => self.apply_choice_and_advance(phase, value),
            GuidedOptionValue::Other => {
                self.open_guided_other();
                InputUpdate::handled()
            }
        }
    }

    pub(super) fn advance_guided_option(&mut self, phase: WorkflowPhase) -> InputUpdate {
        let finished = self
            .engagement
            .guided_scan_mut()
            .is_none_or(GuidedScanFlow::advance_option);
        if finished {
            return self.launch_guided_phase(phase);
        }
        InputUpdate::handled()
    }

    pub(super) fn submit_option_other(&mut self, phase: WorkflowPhase, draft: &str) -> InputUpdate {
        let Some(target) = self.current_guided_option().cloned() else {
            return self.advance_guided_option(phase);
        };
        let Some(spec) = self.planning_option_spec(target.task, &target.option_name) else {
            self.set_guided_error("the selected option is no longer available");
            return InputUpdate::handled();
        };
        match coerce_raw_option_value(&spec, draft) {
            Ok(value) => self.apply_other_option_value(phase, target.task, &spec, value),
            Err(error) => {
                self.set_guided_error(error.to_string());
                InputUpdate::handled()
            }
        }
    }

    pub(super) fn current_guided_option(&self) -> Option<&GuidedOptionTarget> {
        self.engagement.guided_scan()?.current_option()
    }

    pub(super) fn can_accept_remaining_guided_defaults(&self) -> bool {
        let Some(flow) = self.engagement.guided_scan() else {
            return false;
        };
        let remaining = flow.remaining_option_targets();
        !remaining.is_empty() && remaining.iter().all(|target| self.option_can_keep(target))
    }

    pub(super) fn accept_remaining_guided_defaults(&mut self, phase: WorkflowPhase) -> InputUpdate {
        if !self.can_accept_remaining_guided_defaults() {
            return InputUpdate::handled();
        }
        self.launch_guided_phase(phase)
    }

    pub(super) fn guided_option_choices(&self) -> Vec<GuidedOptionChoice> {
        let Some(target) = self.current_guided_option() else {
            return Vec::new();
        };
        let Some(spec) = self.planning_option_spec(target.task, &target.option_name) else {
            return Vec::new();
        };
        let current = self
            .resolved_input_for_planning_task(target.task)
            .ok()
            .and_then(|input| input.get(&spec.name).cloned());
        option_choices(&spec, current)
    }

    fn apply_choice_and_advance(&mut self, phase: WorkflowPhase, value: Value) -> InputUpdate {
        if self.apply_guided_option_value(value) {
            self.advance_guided_option(phase)
        } else {
            InputUpdate::handled()
        }
    }

    fn option_can_keep(&self, target: &GuidedOptionTarget) -> bool {
        let Some(spec) = self.planning_option_spec(target.task, &target.option_name) else {
            return false;
        };
        !spec.required
            || self
                .resolved_input_for_planning_task(target.task)
                .ok()
                .and_then(|input| input.get(&spec.name).cloned())
                .is_some()
    }

    fn apply_guided_option_value(&mut self, value: Value) -> bool {
        let Some(target) = self.current_guided_option().cloned() else {
            return true;
        };
        let Some(spec) = self.planning_option_spec(target.task, &target.option_name) else {
            self.set_guided_error("the selected option is no longer available");
            return false;
        };
        match self.set_planning_option_override(target.task, &spec, value) {
            Ok(()) => true,
            Err(error) => {
                self.set_guided_error(error.to_string());
                false
            }
        }
    }

    fn finish_other_option(&mut self, phase: WorkflowPhase) -> InputUpdate {
        self.edit_guided_flow(GuidedScanFlow::close_other);
        self.advance_guided_option(phase)
    }

    fn apply_other_option_value(
        &mut self,
        phase: WorkflowPhase,
        task: PlanningTaskId,
        spec: &OptionSpec,
        value: Value,
    ) -> InputUpdate {
        if let Err(error) = self.set_planning_option_override(task, spec, value.clone()) {
            self.set_guided_error(error.to_string());
            return InputUpdate::handled();
        }
        self.set_guided_acknowledgement(format!(
            "Accepted {} = {}",
            humanize_option_name(&spec.name),
            format_option_value(&value)
        ));
        self.finish_other_option(phase)
    }

    fn guided_option_targets(&self) -> Vec<GuidedOptionTarget> {
        let picker = self.engagement.planning_picker();
        build_execution_plan(picker.tasks(), picker.selected(), picker.rebuild())
            .into_iter()
            .flat_map(|task| self.guided_option_targets_for_task(task))
            .collect()
    }

    fn guided_option_targets_for_task(&self, task: PlanningTaskId) -> Vec<GuidedOptionTarget> {
        let Some(tool) = self.registry().resolve_tool(task.tool_name()) else {
            return Vec::new();
        };
        tool.options
            .iter()
            .filter(|spec| guided_option_is_visible(self, task, spec))
            .map(|spec| GuidedOptionTarget {
                task,
                option_name: spec.name.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{PlanningArtifactState, PlanningTaskRow};
    use std::{collections::BTreeSet, path::PathBuf};

    fn planning_row(id: PlanningTaskId, artifact_state: PlanningArtifactState) -> PlanningTaskRow {
        PlanningTaskRow {
            id,
            label: id.label(),
            tool_name: id.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state,
            artifact_modified: None,
            model_backed: id.is_model_backed(),
            required_cli: id.required_cli(),
            cli_available: true,
            blocker: None,
        }
    }

    #[test]
    fn option_targets_omit_selected_tasks_outside_the_runnable_rows() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let selected = [
            PlanningTaskId::GatherRepoContext,
            PlanningTaskId::ScanCodeql,
        ]
        .into_iter()
        .collect();
        app.engagement.planning_picker_mut().open(
            vec![planning_row(
                PlanningTaskId::ScanCodeql,
                PlanningArtifactState::Missing,
            )],
            selected,
        );

        let targets = app.guided_option_targets();

        assert!(!targets.is_empty());
        assert!(targets
            .iter()
            .all(|target| target.task == PlanningTaskId::ScanCodeql));
    }

    #[test]
    fn option_targets_skip_cached_rows_until_they_are_marked_for_rebuild() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let task = PlanningTaskId::GatherRepoContext;
        let selected: BTreeSet<PlanningTaskId> = [task].into_iter().collect();
        app.engagement.planning_picker_mut().open(
            vec![planning_row(task, PlanningArtifactState::Cached)],
            selected,
        );

        assert!(app.guided_option_targets().is_empty());

        app.engagement.planning_picker_mut().mark_rebuild(task);
        let targets = app.guided_option_targets();
        assert!(!targets.is_empty());
        assert!(targets.iter().all(|target| target.task == task));
    }
}
