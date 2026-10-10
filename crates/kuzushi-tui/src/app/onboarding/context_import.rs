//! Visible context import uses the existing prepared tool and options editor.
use crate::app::state_transitions::InputUpdate;
use crate::app::{PickerFocus, PlanningTaskId, SetupEditor};
use crate::ShellApp;
use anyhow::Result;

impl ShellApp {
    pub(crate) fn context_import_selected(&self) -> bool {
        self.engagement
            .planning_picker()
            .selected()
            .contains(&PlanningTaskId::ImportThreatModel)
    }

    pub(crate) fn validate_context_import_plan(&self, tasks: &[PlanningTaskId]) -> Result<()> {
        if !tasks.contains(&PlanningTaskId::ImportThreatModel) {
            return Ok(());
        }
        anyhow::ensure!(
            !tasks
                .iter()
                .any(|task| task.tool_name() == "threat-model:build"),
            "Choose context import or context generation in this Map plan; each has its own review"
        );
        self.validated_context_import_input().map(|_| ())
    }

    pub(crate) fn validated_context_import_input(&self) -> Result<serde_json::Value> {
        let input = self.resolved_input_for_planning_task(PlanningTaskId::ImportThreatModel)?;
        kuzushi_core::capabilities::threat_model::validate_threat_model_import_source(&input)?;
        Ok(input)
    }

    pub(crate) fn open_setup_import_options(&mut self) -> InputUpdate {
        if !self
            .engagement
            .planning_picker_mut()
            .set_cursor_to_task(PlanningTaskId::ImportThreatModel)
        {
            self.set_warn_notice(
                "setup",
                "Context import is unavailable in this plan. Reopen Setup to select it.",
            );
            return InputUpdate::handled();
        }
        self.router.setup_mut().begin_editor(SetupEditor::Plan);
        let picker = self.engagement.planning_picker_mut();
        picker.set_return_to_setup(true);
        picker.set_focus(PickerFocus::OptionsPane);
        self.clamp_planning_option_cursor();
        let path_index = self
            .current_planning_tool_options()
            .and_then(|mut options| options.position(|option| option.name == "path"))
            .unwrap_or(0);
        self.move_planning_option_cursor(path_index as isize);
        InputUpdate::handled()
    }
}

#[cfg(test)]
mod tests;
