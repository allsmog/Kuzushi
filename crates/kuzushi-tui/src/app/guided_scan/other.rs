use super::*;
use crate::app::state_transitions::InputUpdate;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl ShellApp {
    pub(super) fn guided_other_is_open(&self) -> bool {
        self.engagement
            .guided_scan()
            .is_some_and(GuidedScanFlow::other_open)
    }

    pub(super) fn reduce_guided_other_key(&mut self, key: KeyEvent) -> InputUpdate {
        if guided_other_releases_to_shared_cancel(key) {
            return InputUpdate::ignored();
        }
        if guided_other_deletes_word(key) {
            self.delete_guided_other_word();
            return InputUpdate::handled();
        }
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return InputUpdate::handled();
        }
        self.reduce_guided_other_code(key.code)
    }

    fn delete_guided_other_word(&mut self) {
        self.edit_guided_flow(|flow| {
            if let Some(editor) = flow.other_editor_mut() {
                editor.delete_word_left();
            }
        });
    }

    fn reduce_guided_other_code(&mut self, code: KeyCode) -> InputUpdate {
        if self.handle_guided_other_control(code) {
            return InputUpdate::handled();
        }
        if let KeyCode::Enter = code {
            return self.submit_guided_other();
        }
        self.edit_guided_other_text(code);
        InputUpdate::handled()
    }

    fn handle_guided_other_control(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Esc => self.edit_guided_flow(GuidedScanFlow::close_other),
            KeyCode::Backspace => self.edit_guided_flow(|flow| {
                if let Some(editor) = flow.other_editor_mut() {
                    editor.backspace();
                }
            }),
            _ => return false,
        }
        true
    }

    fn edit_guided_other_text(&mut self, code: KeyCode) {
        if let KeyCode::Char(ch) = code {
            self.edit_guided_flow(|flow| {
                if let Some(editor) = flow.other_editor_mut() {
                    editor.insert_char_at_cursor(ch);
                }
            });
            return;
        }
        let Some(edit) = guided_other_editor_action(code) else {
            return;
        };
        self.edit_guided_flow(|flow| {
            if let Some(editor) = flow.other_editor_mut() {
                edit(editor);
            }
        });
    }

    fn guided_other_submission(&self) -> Option<(GuidedScanStage, String)> {
        let flow = self.engagement.guided_scan()?;
        let draft = flow.expanded_other_draft()?;
        Some((flow.stage(), draft.trim().to_string()))
    }

    fn submit_guided_other(&mut self) -> InputUpdate {
        let Some((stage, draft)) = self.guided_other_submission() else {
            return InputUpdate::handled();
        };
        if draft.is_empty() {
            self.set_guided_error("enter a value, module name, or instruction");
            return InputUpdate::handled();
        }
        match stage {
            GuidedScanStage::MapRoute => self.submit_map_route_other(&draft),
            GuidedScanStage::ModuleSelection(phase) => {
                self.submit_module_selection_other(phase, &draft)
            }
            GuidedScanStage::ContextPrerequisite => self.submit_context_other(&draft),
            GuidedScanStage::ConfigureOptions(phase) => self.submit_option_other(phase, &draft),
            GuidedScanStage::Running(_) | GuidedScanStage::AwaitingResult { .. } => {
                InputUpdate::handled()
            }
        }
    }

    fn submit_map_route_other(&mut self, draft: &str) -> InputUpdate {
        let normalized = draft.to_ascii_lowercase();
        if self.has_accepted_map() && normalized.contains("scan") {
            self.prepare_guided_phase(WorkflowPhase::Scan);
            return InputUpdate::handled();
        }
        self.apply_freeform_map_route(&normalized);
        InputUpdate::handled()
    }

    fn apply_freeform_map_route(&mut self, normalized: &str) {
        if contains_map_rerun_intent(normalized) {
            self.mark_recommended_map_for_rebuild();
            self.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
        } else if normalized.contains("map") || normalized.contains("module") {
            self.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
        } else {
            self.set_guided_error(
                "could not apply that answer; say continue to Scan, rerun Map, or choose Map modules",
            );
        }
    }

    fn submit_module_selection_other(&mut self, _phase: WorkflowPhase, draft: &str) -> InputUpdate {
        let rows = self.engagement.planning_picker().tasks().to_vec();
        let matches = matching_guided_tasks(&rows, draft);
        if matches.is_empty() {
            self.set_guided_error("no phase module matched that text; use a label or tool name");
            return InputUpdate::handled();
        }
        let labels = matched_task_labels(&rows, &matches);
        let current = self.engagement.planning_picker().selected();
        let proposed = match proposed_guided_selection(&rows, &matches, current) {
            Ok(proposed) => proposed,
            Err(error) => {
                self.set_guided_error(error.to_string());
                return InputUpdate::handled();
            }
        };
        let selected = proposed.len();
        *self.engagement.planning_picker_mut().selected_mut() = proposed;
        self.edit_guided_flow(GuidedScanFlow::close_other);
        self.focus_guided_module_continue();
        self.set_guided_acknowledgement(format!(
            "Added {} · {selected} selected",
            labels.join(", ")
        ));
        InputUpdate::handled()
    }

    fn submit_context_other(&mut self, draft: &str) -> InputUpdate {
        let normalized = draft.to_ascii_lowercase();
        if normalized.contains("build") || normalized.contains("yes") {
            return self.accept_context_prerequisite();
        }
        if normalized.contains("review") || normalized.contains("module") {
            self.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
            return InputUpdate::handled();
        }
        self.set_guided_error("say build context or review modules");
        InputUpdate::handled()
    }
}

type GuidedOtherEditorAction = fn(&mut EditorState);

const GUIDED_OTHER_EDITOR_ACTIONS: &[(KeyCode, GuidedOtherEditorAction)] = &[
    (KeyCode::Delete, EditorState::delete_forward),
    (KeyCode::Left, EditorState::move_cursor_left),
    (KeyCode::Right, EditorState::move_cursor_right),
    (KeyCode::Home, EditorState::move_cursor_home),
    (KeyCode::End, EditorState::move_cursor_end),
];

fn guided_other_editor_action(code: KeyCode) -> Option<GuidedOtherEditorAction> {
    GUIDED_OTHER_EDITOR_ACTIONS
        .iter()
        .find_map(|(candidate, action)| (*candidate == code).then_some(*action))
}

fn guided_other_releases_to_shared_cancel(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
}

fn guided_other_deletes_word(key: KeyEvent) -> bool {
    let ctrl_w = key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('w');
    let modified_backspace = key.code == KeyCode::Backspace
        && key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    ctrl_w || modified_backspace
}

fn contains_map_rerun_intent(value: &str) -> bool {
    ["rerun", "re-run", "rebuild", "refresh"]
        .iter()
        .any(|keyword| value.contains(keyword))
}

fn matching_guided_tasks(rows: &[PlanningTaskRow], draft: &str) -> Vec<PlanningTaskId> {
    let needles = draft
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    rows.iter()
        .filter(|row| row_matches_needles(row, &needles))
        .map(|row| row.id)
        .collect()
}

fn matched_task_labels(rows: &[PlanningTaskRow], matches: &[PlanningTaskId]) -> Vec<String> {
    rows.iter()
        .filter(|row| matches.contains(&row.id))
        .map(|row| row.label.to_string())
        .collect()
}

fn proposed_guided_selection(
    rows: &[PlanningTaskRow],
    matches: &[PlanningTaskId],
    current: &std::collections::BTreeSet<PlanningTaskId>,
) -> anyhow::Result<std::collections::BTreeSet<PlanningTaskId>> {
    let mut proposed = current.clone();
    for task in matches.iter().copied() {
        if proposed.contains(&task) {
            continue;
        }
        ensure_guided_toggle_succeeded(toggle_planning_row(task, rows, &mut proposed))?;
    }
    Ok(proposed)
}

fn ensure_guided_toggle_succeeded(outcome: ToggleOutcome) -> anyhow::Result<()> {
    match outcome {
        ToggleOutcome::On { .. } => Ok(()),
        ToggleOutcome::MissingCli { task, cli } => {
            anyhow::bail!("{} requires `{cli}` on PATH", task.label())
        }
        ToggleOutcome::MissingPrereq { reason, .. } => anyhow::bail!(reason),
        ToggleOutcome::Off { task } | ToggleOutcome::Blocked { task, .. } => {
            anyhow::bail!("{} could not be added to this plan", task.label())
        }
    }
}

fn row_matches_needles(row: &PlanningTaskRow, needles: &[String]) -> bool {
    needles.iter().any(|needle| {
        row.label.to_ascii_lowercase().contains(needle)
            || row.tool_name.to_ascii_lowercase().contains(needle)
    })
}
