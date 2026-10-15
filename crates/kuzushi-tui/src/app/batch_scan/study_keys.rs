use crate::app::{
    state_transitions::{InputUpdate, ViewHotkeyAction},
    ShellApp,
};
use crate::ui_view_models::study_config::{
    study_config_area, study_detail_lines, study_projection, study_reader_layout,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};

impl ShellApp {
    pub(super) fn handle_study_form_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(update) = self.handle_study_editor_key(key) {
            return update;
        }
        self.handle_study_navigation_key(key)
    }

    fn handle_study_navigation_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
            return InputUpdate::handled();
        }
        if self.review_study_is_open() {
            return self.handle_review_study_key(key.code);
        }
        if self.study_notice_captures_escape() {
            return self.handle_study_notice_key(key.code);
        }
        self.handle_study_subview_key(key.code)
            .unwrap_or_else(|| self.handle_study_list_key(key.code))
    }

    fn handle_study_editor_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        self.handle_context_case_name_key(key)
            .or_else(|| self.handle_brief_key(key))
            .or_else(|| self.handle_regeneration_guidance_key(key))
            .or_else(|| self.handle_context_edit_key(key))
    }

    fn handle_study_subview_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        self.handle_optional_resource_key(code)
            .or_else(|| self.handle_context_matrix_key(code))
            .or_else(|| self.handle_context_result_key(code))
            .or_else(|| self.handle_study_picker_key(code))
    }

    fn handle_optional_resource_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if self.study_resource_picker().is_some() {
            return Some(self.handle_study_resource_key(code));
        }
        None
    }

    fn handle_study_picker_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if self.study_engine_picker().is_some() {
            return Some(self.handle_study_engine_key(code));
        }
        if self.context_generation().is_some() {
            return Some(self.handle_context_generation_key(code));
        }
        if self.study_context_picker().is_some() {
            return Some(self.handle_study_context_key(code));
        }
        self.handle_scope_context_key(code)
    }

    fn handle_study_list_key(&mut self, code: KeyCode) -> InputUpdate {
        if self.handle_study_read_key(code) {
            return InputUpdate::handled();
        }
        if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
            return self.return_from_study_reading();
        }
        if self.scroll_study_detail(code) {
            return InputUpdate::handled();
        }
        study_action(code).map_or_else(InputUpdate::handled, |action| {
            self.apply_batch_scan_hotkey(action)
        })
    }

    fn return_from_study_reading(&mut self) -> InputUpdate {
        if self.close_study_reader() {
            return InputUpdate::handled();
        }
        self.close_batch_config()
    }

    fn handle_study_notice_key(&mut self, code: KeyCode) -> InputUpdate {
        if self.handle_study_read_key(code) {
            return InputUpdate::handled();
        }
        if code == KeyCode::Esc {
            self.clear_notice();
            self.clear_study_preparation_error();
            self.close_study_reader();
            if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
                config.notice = None;
                config.detail_scroll = 0;
            }
        } else {
            self.scroll_study_detail(code);
        }
        InputUpdate::handled()
    }

    fn scroll_study_detail(&mut self, code: KeyCode) -> bool {
        if !matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
            return false;
        }
        let viewport = self.viewport();
        let Some(projection) = study_projection(self) else {
            return false;
        };
        let detail = study_reader_layout(
            study_config_area(viewport.columns, viewport.rows),
            projection.detail_reader_scroll.is_some(),
        )
        .detail;
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        let max = study_detail_lines(&projection, detail.width as usize)
            .len()
            .saturating_sub(detail.height as usize);
        let current = config
            .detail_reader_scroll
            .unwrap_or(config.detail_scroll)
            .min(max);
        let page = usize::from(detail.height.max(1));
        super::study_reader::set_detail_scroll(
            config,
            page_offset(code == KeyCode::PageUp, current, page, max),
        );
        true
    }

    pub(crate) fn handle_study_mouse(&mut self, mouse: MouseEvent) -> Option<InputUpdate> {
        if !self.batch_config_open() {
            return None;
        }
        let code = match mouse.kind {
            MouseEventKind::ScrollUp => KeyCode::PageUp,
            MouseEventKind::ScrollDown => KeyCode::PageDown,
            _ => return Some(InputUpdate::handled()),
        };
        if let Some(update) = self.handle_context_edit_key(KeyEvent::new(code, KeyModifiers::NONE))
        {
            return Some(update);
        }
        self.handle_study_scroll(code)
    }

    fn handle_study_scroll(&mut self, code: KeyCode) -> Option<InputUpdate> {
        if self.batch_number_editor_open() {
            return Some(InputUpdate::handled());
        }
        if let Some(update) = self.handle_study_subview_key(code) {
            return Some(update);
        }
        self.scroll_study_detail(code);
        Some(InputUpdate::handled())
    }
}

fn study_action(code: KeyCode) -> Option<ViewHotkeyAction> {
    use ViewHotkeyAction::*;
    [
        (KeyCode::Up, CampaignCursorPrevious),
        (KeyCode::Char('k'), CampaignCursorPrevious),
        (KeyCode::Down, CampaignCursorNext),
        (KeyCode::Char('j'), CampaignCursorNext),
        (KeyCode::Enter, CampaignOpenDetail),
        (KeyCode::Char('L'), CampaignLaunch),
        (KeyCode::Char('w'), CampaignCycleWorkers),
        (KeyCode::Char('r'), CampaignRefresh),
    ]
    .into_iter()
    .find_map(|(key, action)| (key == code).then_some(action))
}

fn page_offset(previous: bool, current: usize, page: usize, max: usize) -> usize {
    if previous {
        current.saturating_sub(page)
    } else {
        current.saturating_add(page).min(max)
    }
}
