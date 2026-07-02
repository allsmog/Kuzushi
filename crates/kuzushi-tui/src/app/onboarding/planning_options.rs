use super::task_id::PlanningTaskId;
use crate::app::{coerce_raw_option_value, format_option_value};
use crate::ShellApp;
use anyhow::{Context, Result};
use kuzushi_core::modules::{OptionSpec, OptionType};
use kuzushi_core::OptionScope;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

mod persistence;
mod task_input;
#[cfg(test)]
mod tests;

use task_input::{next_enum_value, option_storage_names};
pub(crate) use task_input::{planning_task_explicit_input, planning_task_preset_input};

pub type PlanningOptionOverrides = BTreeMap<PlanningTaskId, BTreeMap<String, Value>>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PickerFocus {
    #[default]
    List,
    OptionsPane,
    Prompt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningOptionEdit {
    pub task: PlanningTaskId,
    pub option_name: String,
    pub draft: String,
}

impl ShellApp {
    pub(crate) fn planning_option_count_for_current_row(&self) -> usize {
        self.current_planning_tool_options()
            .map(|options| options.len())
            .unwrap_or(0)
    }

    pub(crate) fn planning_override_count(&self, task: PlanningTaskId) -> usize {
        self.planning_option_overrides
            .get(&task)
            .map(|values| values.len())
            .unwrap_or(0)
    }

    pub(crate) fn clamp_planning_option_cursor(&mut self) {
        let count = self.planning_option_count_for_current_row();
        if count == 0 {
            self.planning_option_cursor = 0;
            return;
        }
        self.planning_option_cursor = self.planning_option_cursor.min(count - 1);
    }

    pub(crate) fn enter_planning_options_pane(&mut self) {
        if self.planning_option_count_for_current_row() == 0 {
            self.planning_option_error = Some("focused step has no declared options".to_string());
            return;
        }
        self.picker_focus = PickerFocus::OptionsPane;
        self.clamp_planning_option_cursor();
    }

    pub(crate) fn leave_planning_options_pane(&mut self) {
        self.picker_focus = PickerFocus::List;
        self.planning_option_edit = None;
    }

    pub(crate) fn move_planning_option_cursor(&mut self, delta: isize) {
        let count = self.planning_option_count_for_current_row();
        if count == 0 {
            return;
        }
        let current = (self.planning_option_cursor.min(count - 1)) as isize;
        self.planning_option_cursor = (current + delta).rem_euclid(count as isize) as usize;
        self.planning_option_error = None;
    }

    pub(crate) fn begin_planning_option_edit(&mut self) {
        let Some((task, spec)) = self.selected_planning_option_spec() else {
            return;
        };
        if self.option_locked_by_planning_preset(task, &spec.name) {
            self.planning_option_error =
                Some(format!("{} is locked by this step preset", spec.name));
            return;
        }
        let draft = self
            .resolved_input_for_planning_task(task)
            .ok()
            .and_then(|input| input.get(&spec.name).cloned())
            .map(|value| format_option_value(&value))
            .unwrap_or_default();
        self.planning_option_edit = Some(PlanningOptionEdit {
            task,
            option_name: spec.name,
            draft,
        });
        self.planning_option_error = None;
    }

    pub(crate) fn edit_planning_option_draft(&mut self, ch: char) {
        if let Some(edit) = self.planning_option_edit.as_mut() {
            edit.draft.push(ch);
        }
    }

    pub(crate) fn backspace_planning_option_draft(&mut self) {
        if let Some(edit) = self.planning_option_edit.as_mut() {
            edit.draft.pop();
        }
    }

    pub(crate) fn cancel_planning_option_edit(&mut self) {
        self.planning_option_edit = None;
        self.planning_option_error = None;
    }

    pub(crate) fn commit_planning_option_edit(&mut self) {
        let Some(edit) = self.planning_option_edit.clone() else {
            return;
        };
        let Some(spec) = self.planning_option_spec(edit.task, &edit.option_name) else {
            self.planning_option_error = Some("selected option disappeared".to_string());
            self.planning_option_edit = None;
            return;
        };
        match coerce_raw_option_value(&spec, &edit.draft)
            .and_then(|value| self.set_planning_option_override(edit.task, &spec, value))
        {
            Ok(()) => {
                self.planning_option_edit = None;
                self.planning_option_error = None;
            }
            Err(error) => {
                self.planning_option_error = Some(error.to_string());
            }
        }
    }

    pub(crate) fn cycle_selected_planning_option(&mut self) {
        let Some((task, spec)) = self.selected_planning_option_spec() else {
            return;
        };
        if self.option_locked_by_planning_preset(task, &spec.name) {
            self.planning_option_error =
                Some(format!("{} is locked by this step preset", spec.name));
            return;
        }
        let result = match spec.option_type {
            OptionType::Bool => self.cycle_bool_planning_option(task, &spec),
            OptionType::Enum => self.cycle_enum_planning_option(task, &spec),
            _ => {
                self.planning_option_error =
                    Some("Enter edits this option; Space cycles bool/enum only".to_string());
                return;
            }
        };
        if let Err(error) = result {
            self.planning_option_error = Some(error.to_string());
        } else {
            self.planning_option_error = None;
        }
    }

    pub(crate) fn input_for_planning_task_with_options(
        &self,
        task: PlanningTaskId,
    ) -> Result<Value> {
        let explicit = planning_task_explicit_input(task, &self.planning_option_overrides);
        self.registry
            .prepare_tool_input(task.tool_name(), explicit, Some(&self.option_store))
    }

    pub(crate) fn resolved_input_for_planning_task(&self, task: PlanningTaskId) -> Result<Value> {
        self.input_for_planning_task_with_options(task)
    }

    pub(crate) fn planning_option_stored_scope(
        &self,
        tool_name: &str,
        spec: &OptionSpec,
    ) -> Option<OptionScope> {
        option_storage_names(spec).into_iter().find_map(|name| {
            self.option_store
                .effective_stored_value_scope(tool_name, name)
        })
    }

    pub(crate) fn option_locked_by_planning_preset(
        &self,
        task: PlanningTaskId,
        option_name: &str,
    ) -> bool {
        planning_task_preset_input(task)
            .as_object()
            .is_some_and(|object| object.contains_key(option_name))
    }

    fn current_planning_tool_options(&self) -> Option<&[OptionSpec]> {
        let row = self.planning_tasks.get(self.planning_cursor)?;
        let tool = self.registry.resolve_tool(row.tool_name)?;
        Some(tool.options.as_slice())
    }

    pub(super) fn selected_planning_option_spec(&self) -> Option<(PlanningTaskId, OptionSpec)> {
        let row = self.planning_tasks.get(self.planning_cursor)?;
        let tool = self.registry.resolve_tool(row.tool_name)?;
        let spec = tool.options.get(self.planning_option_cursor)?.clone();
        Some((row.id, spec))
    }

    fn planning_option_spec(&self, task: PlanningTaskId, option_name: &str) -> Option<OptionSpec> {
        let tool = self.registry.resolve_tool(task.tool_name())?;
        tool.options
            .iter()
            .find(|spec| spec.name == option_name)
            .cloned()
    }

    fn set_planning_option_override(
        &mut self,
        task: PlanningTaskId,
        spec: &OptionSpec,
        value: Value,
    ) -> Result<()> {
        let prepared = self.validate_planning_option_override(task, spec, value)?;
        let canonical = prepared.get(&spec.name).cloned().unwrap_or(Value::Null);
        self.planning_option_overrides
            .entry(task)
            .or_default()
            .insert(spec.name.clone(), canonical);
        Ok(())
    }

    fn validate_planning_option_override(
        &self,
        task: PlanningTaskId,
        spec: &OptionSpec,
        value: Value,
    ) -> Result<Map<String, Value>> {
        let mut overrides = self.planning_option_overrides.clone();
        overrides
            .entry(task)
            .or_default()
            .insert(spec.name.clone(), value);
        self.registry
            .prepare_tool_input(
                task.tool_name(),
                planning_task_explicit_input(task, &overrides),
                Some(&self.option_store),
            )?
            .as_object()
            .cloned()
            .context("prepared planning input was not a JSON object")
    }

    fn cycle_bool_planning_option(
        &mut self,
        task: PlanningTaskId,
        spec: &OptionSpec,
    ) -> Result<()> {
        let current = self
            .resolved_input_for_planning_task(task)
            .ok()
            .and_then(|input| input.get(&spec.name).and_then(Value::as_bool))
            .unwrap_or(false);
        self.set_planning_option_override(task, spec, Value::Bool(!current))
    }

    fn cycle_enum_planning_option(
        &mut self,
        task: PlanningTaskId,
        spec: &OptionSpec,
    ) -> Result<()> {
        let next = next_enum_value(
            spec,
            self.resolved_input_for_planning_task(task)
                .ok()
                .and_then(|input| {
                    input
                        .get(&spec.name)
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .as_deref(),
        )?;
        self.set_planning_option_override(task, spec, Value::String(next))
    }
}
