use super::*;
use crate::app::state_transitions::{is_quit_chord, InputUpdate};
use crate::app::{FieldEditor, InputMode, ToolOptionEdit};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

mod editing;
#[cfg(test)]
mod tests;

impl ShellApp {
    pub(crate) fn option_browser_rows(&self) -> Vec<crate::ui_view_models::OptionsTableRow> {
        match crate::ui_view_models::options_model(self, self.router.options()).body {
            crate::ui_view_models::OptionsBody::Table(table) => table.rows,
            _ => Vec::new(),
        }
    }

    pub(crate) fn selected_browser_option(&self) -> Option<String> {
        let rows = self.option_browser_rows();
        let selected = self.router.options_browser().selected.as_deref();
        rows.iter()
            .find(|row| Some(row.cells[0].as_str()) == selected)
            .or_else(|| rows.first())
            .map(|row| row.cells[0].clone())
    }

    pub(crate) fn handle_option_browser_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.shell_view() != ShellView::Options || self.input_mode() != InputMode::Navigate {
            return InputUpdate::ignored();
        }
        if !key.modifiers.is_empty() {
            return InputUpdate::ignored();
        }
        self.option_browser_action(key.code)
    }

    fn option_browser_action(&mut self, code: KeyCode) -> InputUpdate {
        if let Some(delta) = option_cursor_delta(code) {
            self.move_browser_option(delta);
            return InputUpdate::handled();
        }
        self.option_browser_detail_action(code)
    }

    fn option_browser_detail_action(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Enter => self.begin_browser_option_edit(),
            KeyCode::PageUp => self.page_browser_option(-1),
            KeyCode::PageDown => self.page_browser_option(1),
            _ => return self.option_browser_filter_action(code),
        }
        InputUpdate::handled()
    }

    fn option_browser_filter_action(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Esc
            && !self.notice_captures_escape()
            && self.restore_support_options_origin()
        {
            return InputUpdate::handled();
        }
        let filter = match code {
            KeyCode::Char('s') => OptionsFilter::Standard,
            KeyCode::Char('a') => OptionsFilter::Advanced,
            KeyCode::Char('m') => OptionsFilter::Missing,
            _ => return InputUpdate::ignored(),
        };
        let tool = self.router.options().tool_name.clone();
        self.show_options(Some(tool), filter);
        InputUpdate::handled()
    }

    fn restore_support_options_origin(&mut self) -> bool {
        let Some((view, mode)) = self.router.options_browser_mut().support_origin.take() else {
            return false;
        };
        self.set_shell_view(view);
        self.set_input_mode(mode);
        self.router.navigation_mut().accept_back_transition(view);
        true
    }

    fn move_browser_option(&mut self, delta: isize) {
        let rows = self.option_browser_rows();
        if rows.is_empty() {
            return;
        }
        let selected = self.selected_browser_option();
        let index = rows
            .iter()
            .position(|row| Some(&row.cells[0]) == selected.as_ref())
            .unwrap_or(0);
        let next = index.saturating_add_signed(delta).min(rows.len() - 1);
        let state = self.router.options_browser_mut();
        state.selected = Some(rows[next].cells[0].clone());
        state.detail_scroll = 0;
        state.notice = None;
    }

    fn page_browser_option(&mut self, direction: isize) {
        let (step, maximum) = crate::renderer::option_detail_page_bounds(self);
        let state = self.router.options_browser_mut();
        state.detail_scroll = state
            .detail_scroll
            .min(maximum)
            .saturating_add_signed(direction * step as isize)
            .min(maximum);
    }
}

fn option_cursor_delta(code: KeyCode) -> Option<isize> {
    match code {
        KeyCode::Up | KeyCode::Char('k') => Some(-1),
        KeyCode::Down | KeyCode::Char('j') => Some(1),
        _ => None,
    }
}
