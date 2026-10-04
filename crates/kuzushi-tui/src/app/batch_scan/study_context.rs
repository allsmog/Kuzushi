use crate::app::{state_transitions::InputUpdate, ShellApp};
use crate::ui_view_models::study_config::study_config_area;
use crate::ui_view_models::study_context::{context_catalog, context_detail_lines, context_layout};
use anyhow::Context;
use crossterm::event::KeyCode;
use kuzushi_core::{ThreatModelRef, WorkspaceTarget};
use serde_json::{json, Value};
use std::sync::Arc;

mod diagram;
pub(crate) use diagram::StudyContextDiagram;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct StudyContextPicker {
    pub(crate) scan_input: Value,
    pub(crate) selected: Option<ThreatModelRef>,
    pub(crate) preview: Option<Arc<StudyContextPreview>>,
    pub(crate) detail_scroll: usize,
    pub(crate) raw: bool,
    pub(crate) diagram: Option<StudyContextDiagram>,
    pub(crate) diagram_visible: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyContextPreview {
    pub(crate) document: Value,
    pub(crate) raw: Vec<String>,
    pub(crate) dfd: crate::ui_view_models::DfdModel,
}

fn context_preview(
    data: &Value,
    target: Option<&std::path::Path>,
) -> anyhow::Result<Arc<StudyContextPreview>> {
    let document = data
        .get("document")
        .filter(|value| value.is_object())
        .context("The exact context reader returned no document.")?;
    let text = serde_json::to_string_pretty(document)?;
    Ok(Arc::new(StudyContextPreview {
        document: document.clone(),
        raw: text.lines().map(str::to_string).collect(),
        dfd: crate::ui_view_models::study_context::context_diagram_model(document, target),
    }))
}

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
        let input = WorkspaceTarget::new(&config.target)
            .and_then(|workspace| super::launch::configured_scan_input(self, &workspace, config));
        match input {
            Ok(input) => self.install_study_context_picker(input),
            Err(error) => {
                self.set_batch_config_notice(format!("Context selection unavailable: {error:#}"))
            }
        }
        InputUpdate::handled()
    }

    fn install_study_context_picker(&mut self, input: Value) {
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
        if self.handle_study_diagram_key(code) {
            return InputUpdate::handled();
        }
        match code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.edit_context_picker(|config| config.context_picker = None)
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_study_context(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_study_context(1),
            KeyCode::Enter => return self.inspect_study_context(),
            KeyCode::Char('g') => self.open_context_generation(),
            KeyCode::Char('v') => self.open_study_context_diagram(),
            KeyCode::Char('a') => self.accept_study_context(),
            _ => self.handle_context_detail_key(code),
        }
        InputUpdate::handled()
    }

    fn edit_context_picker(&mut self, edit: impl FnOnce(&mut super::BatchScanConfig)) {
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
                picker.raw = false;
                picker.diagram = None;
                picker.diagram_visible = false;
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
        InputUpdate::handled_with_effects(self.reduce_run_tool(
            Some("threat-model:read".into()),
            Some(json!({"threatModelRef": reference}).to_string()),
        ))
    }

    pub(super) fn cache_study_context_preview(&mut self, data: &Value) -> bool {
        if data["resolvedFrom"] != "exact-context" {
            return false;
        }
        let target = self.target_owned();
        self.edit_context_picker(|config| {
            let Some(picker) = config.context_picker.as_mut() else {
                return;
            };
            if serde_json::from_value::<ThreatModelRef>(data["modelRef"].clone()).ok()
                == picker.selected
            {
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
            }
        });
        true
    }

    fn accept_study_context(&mut self) {
        let Some(picker) = self.study_context_picker().cloned() else {
            return;
        };
        if picker.selected.is_some() && picker.preview.is_none() {
            self.set_batch_config_notice("Inspect this exact revision with Enter before using it.");
            return;
        }
        self.edit_context_picker(|config| {
            let mut input = picker.scan_input;
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

    fn handle_context_detail_key(&mut self, code: KeyCode) {
        if code == KeyCode::Tab {
            self.edit_context_picker(|config| {
                if let Some(picker) = config.context_picker.as_mut() {
                    picker.raw = !picker.raw;
                    picker.detail_scroll = 0;
                }
            });
            return;
        }
        if matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
            self.page_study_context(code == KeyCode::PageUp);
        }
    }

    fn page_study_context(&mut self, previous: bool) {
        let viewport = self.viewport();
        let area = context_layout(
            study_config_area(viewport.columns, viewport.rows),
            context_catalog(self).rows.len(),
        )
        .detail;
        let max = context_detail_lines(self, area.width as usize)
            .len()
            .saturating_sub(area.height as usize);
        self.edit_context_picker(|config| {
            let Some(picker) = config.context_picker.as_mut() else {
                return;
            };
            let offset = picker.detail_scroll.min(max);
            picker.detail_scroll = if previous {
                offset.saturating_sub(area.height as usize)
            } else {
                offset.saturating_add(area.height as usize).min(max)
            };
        });
    }
}

#[cfg(test)]
mod tests;
