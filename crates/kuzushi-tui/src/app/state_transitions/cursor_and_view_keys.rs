use super::*;

impl ShellApp {
    pub(super) fn handle_cursor_key(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
        let Some(handler) = cursor_key_handler(key.code, modifiers) else {
            return false;
        };
        handler(self);
        true
    }

    pub(super) fn handle_empty_input_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !self.input.is_empty() {
            return false;
        }
        if self.handle_config_view_key(key, modifiers) {
            return true;
        }
        if self.handle_findings_view_key(key, modifiers) {
            return true;
        }
        if matches!(key.code, KeyCode::Up | KeyCode::Down)
            && modifiers.plain
            && self.handle_view_hotkey(key)
        {
            return true;
        }
        modifiers.no_modifiers && self.handle_view_hotkey(key)
    }

    pub(super) fn handle_config_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Config) {
            return false;
        }
        match key.code {
            KeyCode::Up => self.move_model_selection(-1),
            KeyCode::Down => self.move_model_selection(1),
            KeyCode::Enter => self.select_current_model_choice(),
            _ => return false,
        }
        true
    }

    pub(super) fn handle_findings_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Findings) {
            return false;
        }
        match key.code {
            KeyCode::Up => self.findings_cursor = self.findings_cursor.saturating_sub(1),
            KeyCode::Down => {
                self.findings_cursor =
                    (self.findings_cursor + 1).min(self.findings.len().saturating_sub(1));
            }
            _ => return false,
        }
        true
    }

    pub(super) fn handle_history_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.plain {
            return false;
        }
        match key.code {
            KeyCode::Up => self.history_prev(),
            KeyCode::Down => self.history_next(),
            _ => return false,
        }
        true
    }
}

fn cursor_key_handler(code: KeyCode, modifiers: KeyModifierState) -> Option<fn(&mut ShellApp)> {
    if modifiers.ctrl_or_alt() {
        return cursor_table_handler(code, CTRL_CURSOR_KEY_ACTIONS);
    }
    if modifiers.plain {
        return cursor_table_handler(code, PLAIN_CURSOR_KEY_ACTIONS);
    }
    cursor_table_handler(code, UNMODIFIED_CURSOR_KEY_ACTIONS)
}

fn cursor_table_handler(
    code: KeyCode,
    actions: &[(KeyCode, fn(&mut ShellApp))],
) -> Option<fn(&mut ShellApp)> {
    actions
        .iter()
        .find_map(|(candidate, handler)| (*candidate == code).then_some(*handler))
}

const CTRL_CURSOR_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Left, ShellApp::move_cursor_word_left),
    (KeyCode::Right, ShellApp::move_cursor_word_right),
    (KeyCode::Backspace, ShellApp::delete_word_left),
];

const PLAIN_CURSOR_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Left, ShellApp::move_cursor_left),
    (KeyCode::Right, ShellApp::move_cursor_right),
    (KeyCode::Home, ShellApp::move_cursor_home),
    (KeyCode::End, ShellApp::move_cursor_end),
    (KeyCode::Delete, ShellApp::delete_forward),
];

const UNMODIFIED_CURSOR_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Home, ShellApp::move_cursor_home),
    (KeyCode::End, ShellApp::move_cursor_end),
    (KeyCode::Delete, ShellApp::delete_forward),
];
