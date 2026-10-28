//! Read-only document focus keeps tree navigation and its scroll independent.
use super::*;
use crate::ui_view_models::{
    scope_review::{
        scope_detail_scroll, scope_display_lines, scope_review_layout, scope_source_view,
    },
    study_config::study_config_area,
};
use crossterm::event::KeyCode;

impl ShellApp {
    pub(super) fn scope_detail_reader_key(&mut self, code: KeyCode) -> InputUpdate {
        if matches!(code, KeyCode::Tab | KeyCode::BackTab) {
            self.router
                .scope_review_mut()
                .as_mut()
                .unwrap()
                .detail_reader
                .open = false;
            return InputUpdate::handled();
        }
        self.scroll_scope_document(code)
    }

    pub(super) fn scope_reading_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        matches!(code, KeyCode::PageUp | KeyCode::PageDown)
            .then(|| self.scroll_scope_document(code))
    }

    fn scroll_scope_document(&mut self, code: KeyCode) -> InputUpdate {
        let viewport = self.viewport();
        let state = self.scope_review().unwrap();
        let area =
            scope_review_layout(study_config_area(viewport.columns, viewport.rows), state).detail;
        let maximum = scope_display_lines(
            self,
            state,
            &scope_source_view(self, state),
            area.width as usize,
        )
        .len()
        .saturating_sub(area.height as usize);
        let current = scope_detail_scroll(state).min(maximum);
        let Some(offset) = document_offset(code, current, maximum, area.height.max(1) as usize)
        else {
            return InputUpdate::handled();
        };
        let state = self.router.scope_review_mut().as_mut().unwrap();
        if state.detail_reader.open {
            state.detail_reader.scroll = offset;
        } else {
            state.scroll = offset;
        }
        InputUpdate::handled()
    }
}

fn document_offset(code: KeyCode, current: usize, maximum: usize, page: usize) -> Option<usize> {
    let step = match code {
        KeyCode::PageUp | KeyCode::PageDown => page,
        _ => 1,
    };
    match code {
        KeyCode::Home => Some(0),
        KeyCode::End => Some(maximum),
        KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp => Some(current.saturating_sub(step)),
        KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown => {
            Some(current.saturating_add(step).min(maximum))
        }
        _ => None,
    }
}
