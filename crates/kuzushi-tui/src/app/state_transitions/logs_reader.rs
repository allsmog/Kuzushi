use super::*;

impl ShellApp {
    pub(crate) fn handle_logs_reader_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.logs_reader_owns_input() {
            return None;
        }
        if is_quit_chord(key) || !key.modifiers.difference(KeyModifiers::SHIFT).is_empty() {
            return None;
        }
        if !self.router.logs().reader_open() {
            return self.open_logs_reader_key(key);
        }
        Some(self.reduce_logs_reader_key(key.code))
    }

    fn logs_reader_owns_input(&self) -> bool {
        self.shell_view() == ShellView::Logs
            && !self.router.logs().filter_capture()
            && !self.scope_review_is_visible()
    }

    fn open_logs_reader_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if key.code != KeyCode::Char('z') || !key.modifiers.is_empty() || !self.input().is_empty() {
            return None;
        }
        self.router.logs_mut().expand_reader();
        Some(InputUpdate::handled())
    }

    fn reduce_logs_reader_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Char('c') => self.router.logs_mut().toggle_command_text(),
            KeyCode::Esc | KeyCode::Char('z') | KeyCode::Char('q') => {
                self.router.logs_mut().close_reader()
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(1),
            KeyCode::PageUp => self.page_up_current_view(),
            KeyCode::PageDown => self.page_down_current_view(),
            KeyCode::Home | KeyCode::Char('g') => self.router.logs_mut().jump_to_start(),
            KeyCode::End | KeyCode::Char('G') => self.router.logs_mut().follow_tail(),
            _ => {}
        }
        InputUpdate::handled()
    }

    pub(crate) fn close_logs_reader_for_paste(&mut self) {
        if self.shell_view() == ShellView::Logs {
            self.router.logs_mut().close_reader();
        }
    }
}

#[cfg(test)]
mod tests;
