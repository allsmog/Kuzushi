//! Local context associations. Changes require a new frozen plan and approval.
use super::BatchScanConfig;
use crate::app::{state_transitions::InputUpdate, ShellApp};
use crate::ui_view_models::{scope_context, study_config::study_config_area};
use crossterm::event::KeyCode;
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ScopeContextState {
    pub(crate) open: bool,
    pub(crate) cursor: usize,
    pub(crate) scroll: usize,
}

impl ShellApp {
    pub(crate) fn scope_context_config(&self) -> Option<&BatchScanConfig> {
        self.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .filter(|config| config.scope_context.open && config.study.scope_draft.is_some())
    }

    pub(super) fn open_study_context_surface(&mut self) -> InputUpdate {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return InputUpdate::handled();
        };
        if config.study.scope_draft.is_none() {
            return self.open_study_context_picker();
        }
        config.scope_context.open = true;
        config.notice = None;
        InputUpdate::handled()
    }

    pub(super) fn handle_scope_context_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        self.scope_context_config()?;
        match code {
            KeyCode::Esc | KeyCode::Char('q') => self.edit_scope_context(|config| {
                config.scope_context.open = false;
                config.notice = None;
            }),
            KeyCode::Up | KeyCode::Char('k') => self.move_scope_context(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_scope_context(1),
            KeyCode::Enter => self.choose_scope_context(),
            KeyCode::Char('i') => self.set_selected_scope_context(None),
            KeyCode::Char('o') => self.set_selected_scope_context(Some(Value::Null)),
            KeyCode::PageUp | KeyCode::PageDown => self.page_scope_context(code),
            _ => {}
        }
        Some(InputUpdate::handled())
    }

    fn edit_scope_context(&mut self, edit: impl FnOnce(&mut BatchScanConfig)) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            edit(config);
        }
    }

    fn move_scope_context(&mut self, delta: i64) {
        self.edit_scope_context(|config| {
            let count = scope_context::rows(config).len();
            config.scope_context.cursor = (config.scope_context.cursor as i64 + delta)
                .clamp(0, count.saturating_sub(1) as i64)
                as usize;
            config.scope_context.scroll = 0;
            config.notice = None;
        });
    }

    fn choose_scope_context(&mut self) {
        let Some(config) = self.scope_context_config() else {
            return;
        };
        let mut input = match super::launch::configured_scan_input(self, config) {
            Ok(input) => input,
            Err(error) => {
                self.set_batch_config_notice(format!("Context unavailable: {error:#}"));
                return;
            }
        };
        let case = scope_context::selected_case(config).cloned();
        if let Some(reference) = case
            .as_ref()
            .and_then(|case| case.threat_model_ref.as_ref())
        {
            input["threatModelRef"] = reference.clone();
        }
        self.install_study_context_picker(input);
        self.edit_scope_context(|config| {
            if let Some(picker) = &mut config.context_picker {
                picker.scope_id = case.map(|case| case.scope_id);
            }
        });
    }

    fn set_selected_scope_context(&mut self, reference: Option<Value>) {
        let case = self
            .scope_context_config()
            .and_then(scope_context::selected_case)
            .cloned();
        let Some(case) = case else {
            self.set_batch_config_notice("Choose a boundary. Enter edits the common context.");
            return;
        };
        self.apply_scope_context(&case.scope_id, reference);
    }

    pub(super) fn apply_scope_context(&mut self, scope_id: &str, reference: Option<Value>) {
        self.edit_scope_context(|config| {
            if let Err(error) = bind_context(config, scope_id, reference) {
                config.notice = Some(error);
                return;
            }
            config.context_picker = None;
            config.scope_context.scroll = 0;
        });
    }

    fn page_scope_context(&mut self, code: KeyCode) {
        let viewport = self.viewport();
        let area = study_config_area(viewport.columns, viewport.rows);
        self.edit_scope_context(|config| {
            let layout = crate::ui_view_models::study_context::context_layout(
                area,
                scope_context::rows(config).len(),
            );
            let lines = scope_context::detail(config, layout.detail.width as usize);
            let max = lines.len().saturating_sub(layout.detail.height as usize);
            let current = config.scope_context.scroll.min(max);
            config.scope_context.scroll =
                page_offset(code, current, layout.detail.height as usize, max);
        });
    }

    pub(super) fn scope_context_action_unavailable(&mut self, code: KeyCode) -> bool {
        let scoped = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .is_some_and(|config| config.study.scope_draft.is_some());
        if scoped && matches!(code, KeyCode::Char('+') | KeyCode::Char('b')) {
            self.set_batch_config_notice("Context experiments need a separate finite plan. Boundary context selections remain intact.");
            return true;
        }
        false
    }
}

fn bind_context(
    config: &mut BatchScanConfig,
    scope_id: &str,
    reference: Option<Value>,
) -> Result<(), String> {
    let case = config
        .study
        .scope_draft
        .as_mut()
        .and_then(|draft| {
            draft
                .cases
                .iter_mut()
                .find(|case| case.scope_id == scope_id)
        })
        .ok_or("The selected boundary is no longer in this draft. Reopen its context.")?;
    let changed = case.threat_model_ref != reference;
    case.threat_model_ref = reference;
    if changed {
        config.study.invalidate_plan();
    }
    config.notice = Some(format!("Context selected for {scope_id}. Prepare and approve the revised plan; existing spending is retained."));
    Ok(())
}

fn page_offset(code: KeyCode, current: usize, page: usize, max: usize) -> usize {
    if code == KeyCode::PageUp {
        current.saturating_sub(page.max(1))
    } else {
        current.saturating_add(page.max(1)).min(max)
    }
}

#[cfg(test)]
mod tests;
