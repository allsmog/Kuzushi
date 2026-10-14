//! A study-local engine draft. Canonical dispatch owns final validation.
use crate::app::{state_transitions::InputUpdate, ShellApp};
use crossterm::event::KeyCode;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyEnginePicker {
    pub input: Value,
    pub selected: BTreeSet<String>,
    pub order: Vec<String>,
    pub automatic: bool,
    pub cursor: usize,
    pub scroll: usize,
    pub notice: Option<String>,
}

impl StudyEnginePicker {
    fn new(input: Value) -> Self {
        let automatic = input["taskMode"].as_str() != Some("manual");
        let order: Vec<String> = input["tasks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let selected = order.iter().cloned().collect();
        Self {
            input,
            selected,
            order,
            automatic,
            cursor: 0,
            scroll: 0,
            notice: None,
        }
    }

    pub fn prepared_selection(&self) -> Value {
        let mut input = self.input.clone();
        input["taskMode"] = json!(if self.automatic { "auto" } else { "manual" });
        if self.automatic {
            input.as_object_mut().unwrap().remove("tasks");
        } else {
            input["tasks"] = json!(self
                .order
                .iter()
                .filter(|id| self.selected.contains(*id))
                .collect::<Vec<_>>());
        }
        input
    }

    pub fn conflicting_paths(&self) -> Option<&[Value]> {
        let reference = self.input.get("scanScopeRef")?;
        serde_json::from_value::<kuzushi_core::workspace::ScanScopeRef>(reference.clone()).ok()?;
        let paths = self.input.get("paths")?.as_array()?;
        (!paths.is_empty()).then_some(paths.as_slice())
    }

    pub fn needs_scoped_file_tools(&self) -> bool {
        self.input.get("scanScopeRef").is_some()
            && self.input.get("mcps") != Some(&Value::Bool(false))
    }

    fn choose_scoped_file_tools(&mut self) {
        if !self.needs_scoped_file_tools() {
            return;
        }
        self.input["mcps"] = json!(false);
        self.scroll = 0;
        self.notice = Some("Scoped file tools selected for this draft. Shared files provide context only; MCP tools are disabled. Apply and review a new plan before execution. Esc preserves the original choices.".into());
    }

    fn clear_path_conflict(&mut self) {
        if self.conflicting_paths().is_none() {
            return;
        }
        self.input["paths"] = json!([]);
        self.scroll = 0;
        self.notice = Some("Earlier path filters cleared in this draft. Apply to use only the accepted boundary; Esc keeps the original filters.".into());
    }
}

impl ShellApp {
    pub(crate) fn study_engine_picker(&self) -> Option<&StudyEnginePicker> {
        self.router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .engine_picker
            .as_ref()
    }

    pub(super) fn open_study_engine_picker(&mut self) -> InputUpdate {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return InputUpdate::handled();
        };
        let result = super::launch::configured_scan_input(self, config);
        match result {
            Ok(input) => {
                let input = super::scope_study::picker_input(config, input);
                self.router
                    .campaign_mut()
                    .batch_scan_config
                    .as_mut()
                    .unwrap()
                    .engine_picker = Some(StudyEnginePicker::new(input));
                self.focus_current_study_engine();
            }
            Err(error) => {
                self.set_batch_config_notice(format!("Engine selection unavailable: {error:#}"))
            }
        }
        InputUpdate::handled()
    }

    pub(super) fn handle_study_engine_key(&mut self, code: KeyCode) -> InputUpdate {
        if let Some(update) = self.handle_engine_control(code) {
            return update;
        }
        let rows = crate::ui_view_models::study_engines::engine_rows(self);
        let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.engine_picker.as_mut())
        else {
            return InputUpdate::handled();
        };
        match code {
            KeyCode::Up | KeyCode::Char('k') => picker.cursor = picker.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                picker.cursor = (picker.cursor + 1).min(rows.len().saturating_sub(1))
            }
            KeyCode::Enter | KeyCode::Char(' ') => toggle_engine(picker, rows.get(picker.cursor)),
            _ => (),
        }
        picker.scroll = 0;
        InputUpdate::handled()
    }

    fn focus_current_study_engine(&mut self) {
        let rows = crate::ui_view_models::study_engines::engine_rows(self);
        let cursor = rows.iter().position(|row| row.selected).unwrap_or(0);
        if let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.engine_picker.as_mut())
        {
            picker.cursor = cursor;
        }
    }

    fn handle_engine_control(&mut self, code: KeyCode) -> Option<InputUpdate> {
        match code {
            KeyCode::Esc => self.close_study_engine_picker(),
            KeyCode::Char('a') => return Some(self.accept_study_engines()),
            KeyCode::Char('x') => self.clear_study_path_conflict(),
            KeyCode::Char('m') => self.choose_study_scoped_file_tools(),
            KeyCode::PageUp | KeyCode::PageDown => self.scroll_study_engines(code),
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    fn clear_study_path_conflict(&mut self) {
        if let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.engine_picker.as_mut())
        {
            picker.clear_path_conflict();
        }
    }

    fn choose_study_scoped_file_tools(&mut self) {
        if let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.engine_picker.as_mut())
        {
            picker.choose_scoped_file_tools();
        }
    }

    fn accept_study_engines(&mut self) -> InputUpdate {
        let Some(picker) = self.study_engine_picker() else {
            return InputUpdate::handled();
        };
        let mut input = picker.prepared_selection();
        if let Err(error) = kuzushi_core::modules::validate_scan_scope_contract(&input) {
            self.router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .unwrap()
                .engine_picker
                .as_mut()
                .unwrap()
                .notice = Some(format!("Selection needs attention: {error:#}"));
            return InputUpdate::handled();
        }
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        super::scope_study::remove_picker_scope(config, &mut input);
        let changed = config.study.scan_input.as_ref() != Some(&input);
        config.study.scan_input = Some(input);
        if changed {
            config.study.invalidate_plan();
        }
        config.engine_picker = None;
        config.detail_scroll = 0;
        config.notice = Some(engine_selection_notice(changed).into());
        self.refresh_batch_worker_resolution();
        InputUpdate::handled()
    }

    fn close_study_engine_picker(&mut self) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.engine_picker = None;
        }
    }

    fn scroll_study_engines(&mut self, code: KeyCode) {
        let viewport = self.viewport();
        let model = crate::ui_view_models::study_engines::engine_layout(
            viewport.columns,
            viewport.rows,
            crate::ui_view_models::study_engines::engine_rows(self).len(),
        );
        let count =
            crate::ui_view_models::study_engines::engine_detail(self, model.detail.width as usize)
                .len();
        let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.engine_picker.as_mut())
        else {
            return;
        };
        let max = count.saturating_sub(model.detail.height as usize);
        let page = model.detail.height.max(1) as usize;
        picker.scroll = if code == KeyCode::PageUp {
            picker.scroll.saturating_sub(page)
        } else {
            (picker.scroll + page).min(max)
        };
    }
}

fn engine_selection_notice(changed: bool) -> &'static str {
    if changed {
        "Engine choices updated for this study. Prepare a new draft; spending history is retained and no jobs start."
    } else {
        "Engine choices retained. The saved plan and spending history are unchanged. No jobs start."
    }
}

fn toggle_engine(
    picker: &mut StudyEnginePicker,
    row: Option<&crate::ui_view_models::study_engines::StudyEngineRow>,
) {
    let Some(row) = row else {
        return;
    };
    if row.id.is_none() {
        picker.automatic = true;
        picker.notice = None;
        return;
    }
    toggle_explicit_engine(picker, row);
}

fn toggle_explicit_engine(
    picker: &mut StudyEnginePicker,
    row: &crate::ui_view_models::study_engines::StudyEngineRow,
) {
    let id = row.id.as_ref().unwrap();
    if !picker.automatic && picker.selected.remove(id) {
        picker.order.retain(|entry| entry != id);
        picker.notice = None;
        return;
    }
    if row.unsupported.is_some() {
        picker.notice = Some("Unsupported for this scope. Choose another engine or cancel.".into());
        return;
    }
    enable_explicit_engine(picker, id);
}

fn enable_explicit_engine(picker: &mut StudyEnginePicker, id: &str) {
    if picker.automatic {
        picker.selected.clear();
        picker.order.clear();
    }
    picker.automatic = false;
    picker.selected.insert(id.to_string());
    picker.order.push(id.to_string());
    picker.notice = None;
}

#[cfg(test)]
mod tests;
