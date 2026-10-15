use super::*;

impl ShellApp {
    pub(crate) fn tools_support_owns_input(&self) -> bool {
        if self.shell_view() != ShellView::Tools || self.support_input_is_captured() {
            return false;
        }
        if self.input_mode() == InputMode::Prompt
            && (!self.input().is_empty() || !self.router.tools().support_focused())
        {
            return false;
        }
        let model = crate::ui_view_models::tools_model(self);
        model.visible_count == 0 && !model.omitted_support.is_empty()
    }

    fn support_input_is_captured(&self) -> bool {
        self.input_capture_is_active() || crate::ui_view_models::answers_own_input(self)
    }

    pub(super) fn handle_tools_support_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if key.code == KeyCode::Esc && self.notice_captures_escape() {
            return None;
        }
        if !key.modifiers.is_empty() || !self.tools_support_owns_input() {
            return None;
        }
        match key.code {
            KeyCode::Up | KeyCode::Down => self.move_support_selection(key.code),
            KeyCode::Enter => self.open_selected_support_options(),
            KeyCode::Esc => self.release_tools_support_input(),
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    fn release_tools_support_input(&mut self) {
        self.router.tools_mut().release_support_focus();
        self.set_input_mode(InputMode::Prompt);
    }

    fn move_support_selection(&mut self, code: KeyCode) {
        let model = crate::ui_view_models::tools_model(self);
        let selected = model.selected_support_index(self.router.tools().selected_support());
        let next = match code {
            KeyCode::Up => selected.saturating_sub(1),
            _ => selected
                .saturating_add(1)
                .min(model.omitted_support.len() - 1),
        };
        self.router
            .tools_mut()
            .select_support(model.omitted_support[next].tool.clone());
    }

    fn open_selected_support_options(&mut self) {
        let model = crate::ui_view_models::tools_model(self);
        let index = model.selected_support_index(self.router.tools().selected_support());
        let tool = model.omitted_support[index].tool.clone();
        self.router.tools_mut().select_support(tool.clone());
        let origin = (self.shell_view(), self.input_mode());
        self.show_options(Some(tool), OptionsFilter::Standard);
        self.router.options_browser_mut().support_origin = Some(origin);
    }
}

#[cfg(test)]
mod tests;
