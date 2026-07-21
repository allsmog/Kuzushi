use super::*;
use kuzushi_core::modules::OptionSpec;
use serde_json::Value;

mod interaction;
mod lifecycle;
mod option_choices;
mod options;
mod other;
mod presentation_copy;
mod projection;
mod seed_context;
#[cfg(test)]
mod tests;

pub(self) use seed_context::ScanSeedContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GuidedScanStage {
    MapRoute,
    ModuleSelection(WorkflowPhase),
    ContextPrerequisite,
    ConfigureOptions(WorkflowPhase),
    Running(WorkflowPhase),
    AwaitingResult {
        phase: WorkflowPhase,
        attempt_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuidedOptionTarget {
    pub(crate) task: PlanningTaskId,
    pub(crate) option_name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct GuidedScanFlow {
    stage: GuidedScanStage,
    cursor: usize,
    other_editor: Option<EditorState>,
    acknowledgement: Option<String>,
    error: Option<String>,
    option_targets: Vec<GuidedOptionTarget>,
    option_index: usize,
}

impl GuidedScanFlow {
    pub(super) fn new(stage: GuidedScanStage) -> Self {
        Self {
            stage,
            cursor: 0,
            other_editor: None,
            acknowledgement: None,
            error: None,
            option_targets: Vec::new(),
            option_index: 0,
        }
    }

    pub(crate) fn stage(&self) -> GuidedScanStage {
        self.stage.clone()
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn other_open(&self) -> bool {
        self.other_editor.is_some()
    }

    pub(crate) fn other_draft(&self) -> &str {
        self.other_editor
            .as_ref()
            .map(EditorState::input)
            .unwrap_or_default()
    }

    pub(crate) fn other_cursor(&self) -> usize {
        self.other_editor
            .as_ref()
            .map(EditorState::cursor)
            .unwrap_or_default()
    }

    pub(super) fn expanded_other_draft(&self) -> Option<String> {
        self.other_editor.as_ref().map(EditorState::expanded_input)
    }

    pub(super) fn other_editor_mut(&mut self) -> Option<&mut EditorState> {
        self.other_editor.as_mut()
    }

    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub(crate) fn acknowledgement(&self) -> Option<&str> {
        self.acknowledgement.as_deref()
    }

    pub(crate) fn current_option(&self) -> Option<&GuidedOptionTarget> {
        self.option_targets.get(self.option_index)
    }

    pub(crate) fn option_progress(&self) -> (usize, usize) {
        (
            self.option_index.saturating_add(1),
            self.option_targets.len(),
        )
    }

    pub(super) fn remaining_option_targets(&self) -> &[GuidedOptionTarget] {
        self.option_targets
            .get(self.option_index..)
            .unwrap_or_default()
    }

    pub(super) fn set_stage(&mut self, stage: GuidedScanStage) {
        self.stage = stage;
        self.reset_question();
    }

    pub(super) fn bind_result(&mut self, phase: WorkflowPhase, attempt_id: String) {
        self.set_stage(GuidedScanStage::AwaitingResult { phase, attempt_id });
    }

    pub(super) fn begin_options(&mut self, phase: WorkflowPhase, targets: Vec<GuidedOptionTarget>) {
        self.option_targets = targets;
        self.option_index = 0;
        self.set_stage(GuidedScanStage::ConfigureOptions(phase));
    }

    pub(super) fn move_cursor(&mut self, delta: isize, count: usize) {
        if count == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor = (self.cursor as isize + delta).rem_euclid(count as isize) as usize;
        self.acknowledgement = None;
        self.error = None;
    }

    pub(super) fn set_cursor(&mut self, cursor: usize) {
        self.cursor = cursor;
        self.acknowledgement = None;
        self.error = None;
    }

    pub(super) fn open_other(&mut self) {
        self.other_editor = Some(EditorState::default());
        self.acknowledgement = None;
        self.error = None;
    }

    pub(super) fn close_other(&mut self) {
        self.other_editor = None;
        self.error = None;
    }

    pub(super) fn set_error(&mut self, error: impl Into<String>) {
        self.acknowledgement = None;
        self.error = Some(error.into());
    }

    pub(super) fn set_acknowledgement(&mut self, message: impl Into<String>) {
        self.acknowledgement = Some(message.into());
        self.error = None;
    }

    pub(super) fn advance_option(&mut self) -> bool {
        self.option_index += 1;
        self.cursor = 0;
        self.option_index >= self.option_targets.len()
    }

    fn reset_question(&mut self) {
        self.cursor = 0;
        self.other_editor = None;
        self.acknowledgement = None;
        self.error = None;
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GuidedQuestionOption {
    pub(crate) label: String,
    pub(crate) description: String,
    pub(crate) selected: bool,
    pub(crate) recommended: bool,
    pub(crate) other: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GuidedScanQuestionModel {
    pub(crate) header: String,
    pub(crate) prompt: String,
    pub(crate) detail_lines: Vec<String>,
    pub(crate) semantic_keys: std::collections::BTreeSet<kuzushi_core::run_lifecycle::RunCellKey>,
    pub(crate) progress: Option<String>,
    pub(crate) options: Vec<GuidedQuestionOption>,
    pub(crate) cursor: usize,
    pub(crate) multi_select: bool,
    pub(crate) accept_remaining_defaults: bool,
    pub(crate) other_open: bool,
    pub(crate) other_draft: String,
    pub(crate) other_cursor: usize,
    pub(crate) acknowledgement: Option<String>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct GuidedOptionChoice {
    pub(super) label: String,
    pub(super) description: String,
    pub(super) value: GuidedOptionValue,
    pub(super) recommended: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum GuidedOptionValue {
    Keep,
    Set(Value),
    Other,
}

pub(super) fn guided_option_is_visible(
    app: &ShellApp,
    task: PlanningTaskId,
    spec: &OptionSpec,
) -> bool {
    if spec.advanced || spec.evasion || app.option_locked_by_planning_preset(task, &spec.name) {
        return false;
    }
    let name = spec.name.to_ascii_lowercase();
    !name.starts_with('_')
        && !["prompt", "model", "api_key", "token", "credential"]
            .iter()
            .any(|private| name.contains(private))
}
