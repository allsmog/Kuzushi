use super::BatchScanConfig;
use crate::app::{state_transitions::InputUpdate, ShellApp};
use crossterm::event::KeyCode;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyResourceChoice {
    pub(crate) campaign_id: Option<String>,
    pub(crate) label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyResourcePicker {
    pub(crate) choices: Vec<StudyResourceChoice>,
    pub(crate) cursor: usize,
    pub(crate) scroll: usize,
    pub(crate) history: crate::app::ViewDataState<crate::app::StudyHistoryRead>,
}

impl ShellApp {
    pub(crate) fn study_resource_picker(&self) -> Option<&StudyResourcePicker> {
        self.router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .resource_picker
            .as_ref()
    }

    pub(super) fn open_study_resource_picker(&mut self) -> Option<InputUpdate> {
        let config = self.router.campaign().batch_scan_config.as_ref()?;
        if config.study.scope_draft.is_none() && config.study.matrix.cases.is_empty() {
            return None;
        }
        let history = self
            .workbench_cache()
            .borrow()
            .cached_study_history(&config.target);
        let choices = usage_choices(&history, config.prior_campaign_id.as_deref());
        let cursor = choices
            .iter()
            .position(|choice| choice.campaign_id == config.prior_campaign_id)
            .unwrap_or(0);
        let config = self.router.campaign_mut().batch_scan_config.as_mut()?;
        config.resource_picker = Some(StudyResourcePicker {
            choices,
            cursor,
            scroll: 0,
            history,
        });
        config.notice = None;
        Some(InputUpdate::handled())
    }

    pub(super) fn handle_study_resource_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Char('r') {
            return self.refresh_resource_picker_catalogue();
        }
        if matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
            return self.page_study_resource_detail(code);
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return InputUpdate::handled();
        };
        match code {
            KeyCode::Esc => config.resource_picker = None,
            KeyCode::Enter => accept_choice(config),
            KeyCode::Up | KeyCode::Char('k') => move_choice(config, -1),
            KeyCode::Down | KeyCode::Char('j') => move_choice(config, 1),
            _ => {}
        }
        InputUpdate::handled()
    }

    fn refresh_resource_picker_catalogue(&mut self) -> InputUpdate {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return InputUpdate::handled();
        };
        if let Some(picker) = &mut config.resource_picker {
            picker.history = crate::app::ViewDataState::NotRequested;
        }
        let target = config.target.clone();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_study_history(&target);
        InputUpdate::handled()
    }

    pub(super) fn refresh_resource_picker_history(&mut self) {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return;
        };
        if config.resource_picker.is_none() {
            return;
        }
        let history = self
            .workbench_cache()
            .borrow()
            .cached_study_history(&config.target);
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        apply_history(config, history);
    }

    fn page_study_resource_detail(&mut self, code: KeyCode) -> InputUpdate {
        let viewport = self.viewport();
        let model = crate::ui_view_models::study_resource_picker::resource_picker_model(
            self,
            usize::from(viewport.columns.min(120).saturating_sub(4)),
            usize::from(viewport.rows),
        );
        let Some(model) = model else {
            return InputUpdate::handled();
        };
        if let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.resource_picker.as_mut())
        {
            let direction = if code == KeyCode::PageUp { -1 } else { 1 };
            picker.scroll = picker
                .scroll
                .saturating_add_signed(
                    direction * model.page_rows.saturating_sub(1).max(1) as isize,
                )
                .min(model.max_offset);
        }
        InputUpdate::handled()
    }
}

fn usage_choices(
    history: &crate::app::ViewDataState<crate::app::StudyHistoryRead>,
    selected: Option<&str>,
) -> Vec<StudyResourceChoice> {
    let mut choices = vec![StudyResourceChoice {
        campaign_id: None,
        label: "No historical calibration".into(),
    }];
    if let crate::app::ViewDataState::Ready(Ok(catalogue)) = history {
        choices.extend(catalogue.choices.iter().map(history_choice));
    }
    append_named_choice(&mut choices, selected);
    choices
}

fn history_choice(
    study: &kuzushi_core::capabilities::campaign::StudyUsageChoice,
) -> StudyResourceChoice {
    let complete = study.completed_jobs.map_or_else(
        || "completion unknown".into(),
        |count| format!("{count}/{} completed", study.planned_jobs),
    );
    StudyResourceChoice {
        campaign_id: Some(study.campaign_id.clone()),
        label: format!("{} · {complete}", study.campaign_id),
    }
}

fn apply_history(
    config: &mut BatchScanConfig,
    history: crate::app::ViewDataState<crate::app::StudyHistoryRead>,
) {
    let Some(picker) = &mut config.resource_picker else {
        return;
    };
    if picker.history == history {
        return;
    }
    let selected = picker
        .choices
        .get(picker.cursor)
        .and_then(|choice| choice.campaign_id.clone());
    if matches!(history, crate::app::ViewDataState::Ready(Ok(_))) {
        picker.choices = usage_choices(&history, selected.as_deref());
        picker.cursor = picker
            .choices
            .iter()
            .position(|choice| choice.campaign_id == selected)
            .unwrap_or(0);
    }
    picker.history = history;
}

fn append_named_choice(choices: &mut Vec<StudyResourceChoice>, selected: Option<&str>) {
    let Some(id) = selected else { return };
    if !choices
        .iter()
        .any(|choice| choice.campaign_id.as_deref() == Some(id))
    {
        choices.push(StudyResourceChoice {
            campaign_id: Some(id.into()),
            label: format!("{id} · recorded selection"),
        });
    }
}

fn move_choice(config: &mut BatchScanConfig, direction: isize) {
    if let Some(picker) = &mut config.resource_picker {
        picker.cursor = picker
            .cursor
            .saturating_add_signed(direction)
            .min(picker.choices.len().saturating_sub(1));
        picker.scroll = 0;
    }
}

fn accept_choice(config: &mut BatchScanConfig) {
    let Some(picker) = config.resource_picker.take() else {
        return;
    };
    let Some(choice) = picker.choices.get(picker.cursor) else {
        return;
    };
    if config.prior_campaign_id == choice.campaign_id {
        return;
    }
    config.prior_campaign_id = choice.campaign_id.clone();
    config.prior_run_id = None;
    config.study.invalidate_plan();
    config.detail_scroll = 0;
    config.notice = Some("Usage evidence changed. Prepare a new draft for separate approval. Scope, context, model, spending and limits remain unchanged; no jobs started.".into());
}

#[cfg(test)]
mod tests;
