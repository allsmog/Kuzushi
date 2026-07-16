use super::*;
use crate::app::state_transitions::InputUpdate;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::workflow_attempts::PhaseResultAction;

impl ShellApp {
    pub(crate) fn reduce_guided_scan_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(update) = self.guided_key_guard(key) {
            return update;
        }
        if self.apply_guided_navigation_key(key.code) {
            return InputUpdate::handled();
        }
        self.reduce_guided_action_key(key.code)
    }

    fn guided_key_guard(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.guided_scan_question_is_open() {
            return Some(InputUpdate::ignored());
        }
        if self.guided_other_is_open() {
            return Some(self.reduce_guided_other_key(key));
        }
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return Some(InputUpdate::handled());
        }
        None
    }

    pub(crate) fn paste_guided_scan_other(&mut self, text: &str) -> bool {
        let Some(flow) = self.engagement.guided_scan_mut() else {
            return false;
        };
        if !flow.other_open() {
            return false;
        }
        let editor = flow.other_editor_mut().expect("checked Other editor");
        if text.contains('\n') {
            editor.insert_multiline_paste(text);
        } else {
            editor.insert_str_at_cursor(text);
        }
        true
    }

    pub(super) fn open_guided_other(&mut self) {
        self.edit_guided_flow(GuidedScanFlow::open_other);
    }

    fn apply_guided_navigation_key(&mut self, code: KeyCode) -> bool {
        let delta = match code {
            KeyCode::Up | KeyCode::Char('k') => -1,
            KeyCode::Down | KeyCode::Char('j') => 1,
            _ => return false,
        };
        self.move_guided_cursor(delta);
        true
    }

    fn reduce_guided_action_key(&mut self, code: KeyCode) -> InputUpdate {
        if let Some(index) = guided_direct_choice_index(code) {
            return self.activate_guided_index(self.resolve_guided_choice_index(index));
        }
        match code {
            KeyCode::Char(' ') => return self.toggle_focused_guided_module(),
            KeyCode::Char('c') | KeyCode::Char('C') => {
                return self.continue_guided_module_selection()
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                return self.accept_guided_remaining_defaults()
            }
            KeyCode::Tab if self.guided_question_accepts_other() => self.open_guided_other(),
            KeyCode::Esc => self.dismiss_guided_questions(),
            _ => {}
        }
        InputUpdate::handled()
    }

    fn toggle_focused_guided_module(&mut self) -> InputUpdate {
        let Some(flow) = self.engagement.guided_scan() else {
            return InputUpdate::handled();
        };
        if !matches!(flow.stage(), GuidedScanStage::ModuleSelection(_)) {
            return InputUpdate::handled();
        }
        let cursor = flow.cursor();
        if cursor < self.engagement.planning_picker().tasks().len() {
            self.toggle_guided_task(cursor);
        }
        InputUpdate::handled()
    }

    fn guided_question_accepts_other(&self) -> bool {
        self.guided_scan_question_model()
            .is_some_and(|question| question.options.iter().any(|option| option.other))
    }

    fn continue_guided_module_selection(&mut self) -> InputUpdate {
        let Some(GuidedScanStage::ModuleSelection(phase)) =
            self.engagement.guided_scan().map(GuidedScanFlow::stage)
        else {
            return InputUpdate::handled();
        };
        self.finish_guided_module_selection(phase)
    }

    fn accept_guided_remaining_defaults(&mut self) -> InputUpdate {
        let Some(GuidedScanStage::ConfigureOptions(phase)) =
            self.engagement.guided_scan().map(GuidedScanFlow::stage)
        else {
            return InputUpdate::handled();
        };
        self.accept_remaining_guided_defaults(phase)
    }

    fn resolve_guided_choice_index(&self, index: usize) -> usize {
        if index != usize::MAX {
            return index;
        }
        self.guided_scan_question_model()
            .map_or(0, |question| question.cursor)
    }

    fn move_guided_cursor(&mut self, delta: isize) {
        let count = self.guided_choice_count();
        if self.move_guided_result_cursor(delta, count) {
            return;
        }
        self.edit_guided_flow(|flow| flow.move_cursor(delta, count));
    }

    fn move_guided_result_cursor(&mut self, delta: isize, count: usize) -> bool {
        let Some(GuidedScanStage::AwaitingResult { phase, attempt_id }) =
            self.engagement.guided_scan().map(GuidedScanFlow::stage)
        else {
            return false;
        };
        if self
            .engagement
            .unresolved_phase_attempt_by_id(phase, &attempt_id)
            .is_none()
        {
            return true;
        }
        self.ui_mut()
            .move_phase_result_cursor(&attempt_id, count, delta);
        true
    }

    fn guided_choice_count(&self) -> usize {
        self.guided_scan_question_model()
            .map_or(0, |question| question.options.len())
    }

    fn activate_guided_index(&mut self, index: usize) -> InputUpdate {
        let Some(stage) = self.engagement.guided_scan().map(GuidedScanFlow::stage) else {
            return InputUpdate::handled();
        };
        match stage {
            GuidedScanStage::MapRoute => self.activate_map_route(index),
            GuidedScanStage::ModuleSelection(phase) => self.activate_module_selection(phase, index),
            GuidedScanStage::ContextPrerequisite => self.activate_context_choice(index),
            GuidedScanStage::ConfigureOptions(phase) => self.activate_option_choice(phase, index),
            GuidedScanStage::Running(_) => InputUpdate::handled(),
            GuidedScanStage::AwaitingResult { phase, attempt_id } => {
                self.activate_phase_result_choice(phase, &attempt_id, index)
            }
        }
    }

    pub(super) fn activate_map_route(&mut self, index: usize) -> InputUpdate {
        let has_map = self.has_accepted_map();
        if has_map && index == 0 {
            self.prepare_guided_phase(WorkflowPhase::Scan);
            return InputUpdate::handled();
        }
        let rerun_index = usize::from(has_map);
        if index == rerun_index {
            self.mark_recommended_map_for_rebuild();
            self.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
            self.focus_guided_module_continue();
        } else if index == rerun_index + 1 {
            self.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
            self.focus_guided_module_continue();
        } else {
            self.open_guided_other();
        }
        InputUpdate::handled()
    }

    pub(super) fn activate_module_selection(
        &mut self,
        phase: WorkflowPhase,
        index: usize,
    ) -> InputUpdate {
        let task_count = self.engagement.planning_picker().tasks().len();
        if index < task_count {
            self.toggle_guided_task(index);
            return InputUpdate::handled();
        }
        if index == task_count {
            return self.finish_guided_module_selection(phase);
        }
        self.open_guided_other();
        InputUpdate::handled()
    }

    fn toggle_guided_task(&mut self, index: usize) {
        let Some(task) = self.guided_task_at(index) else {
            return;
        };
        let rows = self.engagement.planning_picker().tasks().to_vec();
        let outcome = toggle_planning_row(
            task,
            &rows,
            self.engagement.planning_picker_mut().selected_mut(),
        );
        self.report_guided_toggle_failure(task, outcome);
    }

    fn guided_task_at(&self, index: usize) -> Option<PlanningTaskId> {
        self.engagement
            .planning_picker()
            .tasks()
            .get(index)
            .map(|row| row.id)
    }

    fn report_guided_toggle_failure(&mut self, task: PlanningTaskId, outcome: ToggleOutcome) {
        match outcome {
            ToggleOutcome::MissingCli { cli, .. } => {
                self.set_guided_error(format!("{task:?} requires `{cli}` on PATH"));
            }
            ToggleOutcome::MissingPrereq { reason, .. } => self.set_guided_error(reason),
            _ => {}
        }
    }

    pub(super) fn finish_guided_module_selection(&mut self, phase: WorkflowPhase) -> InputUpdate {
        if self.engagement.planning_picker().selected().is_empty() {
            self.set_guided_error("select at least one module before continuing");
            return InputUpdate::handled();
        }
        if phase == WorkflowPhase::Map && self.map_context_is_missing() {
            self.set_guided_stage(GuidedScanStage::ContextPrerequisite);
            return InputUpdate::handled();
        }
        self.begin_guided_options_or_run(phase)
    }

    fn activate_context_choice(&mut self, index: usize) -> InputUpdate {
        match index {
            0 => self.accept_context_prerequisite(),
            1 => {
                self.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
                InputUpdate::handled()
            }
            _ => {
                self.open_guided_other();
                InputUpdate::handled()
            }
        }
    }

    pub(super) fn accept_context_prerequisite(&mut self) -> InputUpdate {
        self.engagement
            .planning_picker_mut()
            .selected_mut()
            .insert(PlanningTaskId::GatherRepoContext);
        self.begin_guided_options_or_run(WorkflowPhase::Map)
    }

    pub(super) fn launch_guided_phase(&mut self, phase: WorkflowPhase) -> InputUpdate {
        let plan = build_execution_plan(
            self.engagement.planning_picker().tasks(),
            self.engagement.planning_picker().selected(),
            self.engagement.planning_picker().rebuild(),
        );
        if plan.is_empty() && phase == WorkflowPhase::Map && self.has_accepted_map() {
            self.prepare_guided_phase(WorkflowPhase::Scan);
            return InputUpdate::handled();
        }
        if plan.is_empty() {
            return self.report_empty_guided_plan(phase);
        }
        self.set_guided_stage(GuidedScanStage::Running(phase));
        self.accept_planning_picker()
    }

    fn report_empty_guided_plan(&mut self, phase: WorkflowPhase) -> InputUpdate {
        self.set_guided_stage(GuidedScanStage::ModuleSelection(phase));
        self.set_guided_error("the selection has no runnable modules; choose an available module");
        InputUpdate::handled()
    }

    fn activate_phase_result_choice(
        &mut self,
        phase: WorkflowPhase,
        attempt_id: &str,
        index: usize,
    ) -> InputUpdate {
        let Some(action) = self
            .guided_result_actions(phase, attempt_id)
            .get(index)
            .copied()
        else {
            return InputUpdate::handled();
        };
        self.apply_phase_result_command(PhaseResultCommand::from_action(action))
    }

    pub(super) fn guided_result_actions(
        &self,
        phase: WorkflowPhase,
        attempt_id: &str,
    ) -> Vec<PhaseResultAction> {
        let Some(record) = self
            .engagement
            .unresolved_phase_attempt_by_id(phase, attempt_id)
        else {
            return Vec::new();
        };
        self.phase_result_presentation_for(&record.completed)
            .actions
    }

    fn dismiss_guided_questions(&mut self) {
        self.clear_guided_scan();
        self.set_input_mode(InputMode::Prompt);
        self.log("scan", "guided scan questions dismissed; draft preserved");
    }
}

fn guided_direct_choice_index(code: KeyCode) -> Option<usize> {
    match code {
        KeyCode::Enter => Some(usize::MAX),
        KeyCode::Char(ch @ '1'..='9') => Some(ch.to_digit(10).unwrap_or(1) as usize - 1),
        _ => None,
    }
}
