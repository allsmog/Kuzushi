use crate::app::{state_transitions::InputUpdate, ShellApp};
use crate::ui_view_models::study_config::study_config_area;
use crate::ui_view_models::study_context::{
    context_catalog, context_detail_lines, context_reader_layout,
};
use crossterm::event::KeyCode;

use super::StudyContextTextView;

impl ShellApp {
    pub(super) fn handle_context_detail_key(&mut self, code: KeyCode) {
        if let Some(requested) = requested_text_view(code) {
            self.edit_context_picker(|config| {
                if let Some(picker) = config.context_picker.as_mut() {
                    picker.text_view = picker.text_view.toggled(requested);
                    picker.detail_scroll = 0;
                }
            });
            return;
        }
        if matches!(
            code,
            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End
        ) {
            self.scroll_study_context(code);
        }
    }

    fn scroll_study_context(&mut self, code: KeyCode) {
        let viewport = self.viewport();
        let text_view = self
            .study_context_picker()
            .map_or(StudyContextTextView::Summary, |picker| picker.text_view);
        let inspected = self
            .study_context_picker()
            .is_some_and(|picker| picker.preview.is_some());
        let area = context_reader_layout(
            study_config_area(viewport.columns, viewport.rows),
            context_catalog(self).rows.len(),
            text_view,
            inspected,
        )
        .detail;
        let max = context_detail_lines(self, area.width as usize)
            .len()
            .saturating_sub(area.height as usize);
        let step = if matches!(code, KeyCode::Home | KeyCode::End) {
            usize::MAX
        } else {
            area.height as usize
        };
        self.edit_context_picker(|config| {
            let Some(picker) = config.context_picker.as_mut() else {
                return;
            };
            let offset = picker.detail_scroll.min(max);
            picker.detail_scroll = if matches!(code, KeyCode::PageUp | KeyCode::Home) {
                offset.saturating_sub(step)
            } else {
                offset.saturating_add(step).min(max)
            };
        });
    }
}

fn requested_text_view(code: KeyCode) -> Option<StudyContextTextView> {
    match code {
        KeyCode::Tab => Some(StudyContextTextView::Document),
        KeyCode::Char('p') => Some(StudyContextTextView::Scanner),
        _ => None,
    }
}
