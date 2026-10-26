use crate::app::{state_transitions::InputUpdate, ShellApp};
use crate::ui_view_models::study_config::study_config_area;
use crate::ui_view_models::study_context::{
    context_catalog, context_detail_lines, context_reader_layout,
};
use anyhow::Context;
use crossterm::event::KeyCode;
use kuzushi_core::ThreatModelRef;
use serde_json::{json, Value};
use std::sync::Arc;

mod diagram;
mod model;
mod navigation;
mod text_view;
pub(crate) use diagram::StudyContextDiagram;
use model::{context_preview, context_selection_ready, matching_saved_context};
pub(crate) use model::{StudyContextPicker, StudyContextPreview};
pub(crate) use text_view::StudyContextTextView;

impl ShellApp {
    pub(crate) fn study_context_picker(&self) -> Option<&StudyContextPicker> {
        self.router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .context_picker
            .as_ref()
    }

    pub(super) fn open_study_context_picker(&mut self) -> InputUpdate {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return InputUpdate::handled();
        };
        let input = super::launch::configured_scan_input(self, config);
        match input {
            Ok(input) => self.install_study_context_picker(input),
            Err(error) => {
                self.set_batch_config_notice(format!("Context selection unavailable: {error:#}"))
            }
        }
        InputUpdate::handled()
    }

    pub(super) fn install_study_context_picker(&mut self, input: Value) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let selected = match serde_json::from_value(input["threatModelRef"].clone()) {
            Ok(selected) => selected,
            Err(error) => {
                config.notice = Some(format!("Invalid selected context reference: {error}"));
                return;
            }
        };
        config.context_picker = Some(StudyContextPicker {
            scan_input: input,
            selected,
            ..Default::default()
        });
        config.notice = None;
    }

    pub(super) fn handle_study_context_key(&mut self, code: KeyCode) -> InputUpdate {
        if let Some(update) = self.handle_context_overlay_key(code) {
            return update;
        }
        match code {
            KeyCode::Esc | KeyCode::Char('q') => self.close_study_context_picker(),
            KeyCode::Up | KeyCode::Char('k') => self.move_study_context(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_study_context(1),
            KeyCode::Enter => return self.inspect_study_context(),
            KeyCode::Char('g') => self.open_context_generation(),
            KeyCode::Char('v') => self.open_study_context_diagram(),
            KeyCode::Char('a') => self.accept_study_context(),
            KeyCode::Char('e') => self.open_context_editor(),
            KeyCode::Char('c') => return self.check_study_context(),
            KeyCode::Char('d') => return self.compare_study_context(),
            KeyCode::Char(' ') => self.open_context_actions(),
            KeyCode::Char('m') => return self.review_existing_context_map(),
            KeyCode::Char('+') => self.add_inspected_context_case(false),
            KeyCode::Char('b') => self.add_inspected_context_case(true),
            _ => self.handle_context_detail_key(code),
        }
        InputUpdate::handled()
    }

    fn handle_context_modal_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        self.handle_context_comparison_key(code)
            .or_else(|| self.handle_context_actions_key(code))
            .or_else(|| self.handle_study_diagram_key(code))
    }

    fn handle_context_overlay_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if let Some(update) = self.handle_context_modal_key(code) {
            return Some(update);
        }
        if self.scope_context_action_unavailable(code) {
            return Some(InputUpdate::handled());
        }
        self.handle_regeneration_context_selection_key(code)
    }

    fn close_study_context_picker(&mut self) {
        if self
            .study_context_picker()
            .is_some_and(|picker| picker.regeneration_entry)
        {
            self.close_batch_config();
            return;
        }
        self.edit_context_picker(|config| {
            let picker = config.context_picker.take();
            if picker
                .as_ref()
                .is_some_and(|picker| picker.matrix_case_id.is_some())
            {
                config.study.matrix.open = true;
            }
            let generation = picker.and_then(|picker| picker.return_generation);
            if let Some(generation) = generation {
                config.context_generation = Some(*generation);
            }
        });
    }

    pub(super) fn edit_context_picker(&mut self, edit: impl FnOnce(&mut super::BatchScanConfig)) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            edit(config);
        }
    }

    fn move_study_context(&mut self, delta: i64) {
        let catalog = context_catalog(self);
        let Some(picker) = self.study_context_picker() else {
            return;
        };
        let current = catalog
            .rows
            .iter()
            .position(|row| row.reference == picker.selected)
            .unwrap_or(0);
        let next =
            (current as i64 + delta).clamp(0, catalog.rows.len().saturating_sub(1) as i64) as usize;
        let selected = catalog.rows.get(next).and_then(|row| row.reference.clone());
        self.edit_context_picker(|config| {
            if let Some(picker) = config.context_picker.as_mut() {
                picker.selected = selected;
                picker.preview = None;
                picker.detail_scroll = 0;
                picker.text_view = StudyContextTextView::Summary;
                picker.diagram = None;
                picker.diagram_visible = false;
                picker.map_attempt_id = None;
                picker.editor_visible = false;
                picker.comparison = None;
            }
        });
    }

    pub(super) fn inspect_study_context(&mut self) -> InputUpdate {
        let Some(reference) = self
            .study_context_picker()
            .and_then(|picker| picker.selected.clone())
        else {
            return InputUpdate::handled();
        };
        if self.has_running_work() {
            self.set_batch_config_notice(
                "Wait for active work, then inspect this context revision.",
            );
            return InputUpdate::handled();
        }
        self.set_batch_config_notice(
            "Reading the selected immutable context. No model request is made.",
        );
        let input = self.study_context_inspection_input(&reference);
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some("threat-model:read".into()), Some(input.to_string())),
        )
    }

    fn study_context_inspection_input(&self, reference: &ThreatModelRef) -> Value {
        let mut input = json!({"threatModelRef":reference});
        let saved = self
            .study_context_picker()
            .map(|picker| &picker.scan_input)
            .filter(|value| matching_saved_context(value, reference))
            .or_else(|| {
                self.router
                    .campaign()
                    .batch_scan_config
                    .as_ref()?
                    .study
                    .receipt
                    .as_ref()
                    .map(|receipt| &receipt.scan_input)
            });
        if let Some(saved) = saved.filter(|value| matching_saved_context(value, reference)) {
            input["threatModelDigestRef"] = saved["threatModelDigestRef"].clone();
        }
        input
    }

    fn review_existing_context_map(&mut self) -> InputUpdate {
        let Some(picker) = self.study_context_picker() else {
            return InputUpdate::handled();
        };
        let has_recorded_map = picker.map_attempt_id.is_some();
        let Some(reference) = picker.selected.clone().filter(|_| picker.preview.is_some()) else {
            self.set_batch_config_notice(
                "Inspect an exact revision with Enter before reviewing Map.",
            );
            return InputUpdate::handled();
        };
        if self.has_running_work() {
            self.set_batch_config_notice("Wait for active work, then review this context as Map.");
            return InputUpdate::handled();
        }
        if has_recorded_map && self.open_reviewed_context_map() {
            return InputUpdate::handled();
        }
        self.dispatch_context_action("campaign:context-map", json!({"threatModelRef":reference}))
    }

    pub(super) fn cache_study_context_preview(&mut self, data: &Value) -> bool {
        if data["resolvedFrom"] != "exact-context" {
            return false;
        }
        if self.cache_context_comparison(data) {
            return true;
        }
        self.install_matching_context_preview(data);
        true
    }

    fn install_matching_context_preview(&mut self, data: &Value) {
        if data["target"].as_str().map(std::path::Path::new) != self.target() {
            return;
        }
        if !self.matches_study_context_read(data) {
            return;
        }
        let target = self.target_owned();
        self.edit_context_picker(|config| {
            let Some(picker) = config.context_picker.as_mut() else {
                return;
            };
            match context_preview(data, target.as_deref()) {
                Ok(preview) => {
                    picker.preview = Some(preview);
                    picker.detail_scroll = 0;
                    config.notice = None;
                }
                Err(error) => {
                    picker.preview = None;
                    picker.diagram_visible = false;
                    config.notice = Some(format!("Context preview unavailable: {error:#}"));
                }
            }
        });
    }

    fn matches_study_context_read(&self, data: &Value) -> bool {
        let Some(reference) = self
            .study_context_picker()
            .and_then(|picker| picker.selected.as_ref())
        else {
            return false;
        };
        let expected = self.study_context_inspection_input(reference);
        data["modelRef"] == json!(reference)
            && expected.get("threatModelDigestRef")
                == data["scannerContextPreview"].get("frozenReference")
    }

    fn accept_study_context(&mut self) {
        let Some(picker) = self.study_context_picker().cloned() else {
            return;
        };
        if let Err(reason) = context_selection_ready(&picker) {
            self.set_batch_config_notice(reason);
            return;
        }
        if self.accept_bound_context(&picker) {
            return;
        }
        self.edit_context_picker(|config| {
            let mut input = picker.scan_input;
            input.as_object_mut().unwrap().remove("threatModelDigestRef");
            input["threatModelRef"] = json!(picker.selected);
            if config.study.scan_input.as_ref() != Some(&input) {
                config.study.invalidate_plan();
            }
            config.study.scan_input = Some(input);
            config.context_picker = None;
            config.detail_scroll = 0;
            config.notice = Some("Context selected for this study. Prepare a new plan before approval; existing consumption is retained.".into());
        });
    }

    fn accept_bound_context(&mut self, picker: &StudyContextPicker) -> bool {
        if let Some(scope_id) = picker.scope_id.as_deref() {
            self.apply_scope_context(scope_id, Some(json!(picker.selected)));
            return true;
        }
        if let Some(case_id) = picker.matrix_case_id.as_deref() {
            self.replace_context_case(case_id, json!(picker.selected));
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests;
