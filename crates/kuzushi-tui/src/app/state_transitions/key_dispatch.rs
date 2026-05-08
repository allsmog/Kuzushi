use super::*;

impl ShellApp {
    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.handle_modal_key(key) {
            return;
        }

        self.update_quit_chord_arm(key);
        if self.handle_story_toggle_key(key) {
            return;
        }

        let modifiers = KeyModifierState::new(key);
        self.reset_completion_cycle_for_key(key);

        if self.handle_control_key(key, modifiers)
            || self.handle_cursor_key(key, modifiers)
            || self.handle_empty_input_view_key(key, modifiers)
            || self.handle_history_key(key, modifiers)
            || self.handle_text_key(key)
        {
            return;
        }
    }

    pub(super) fn handle_modal_key(&mut self, key: KeyEvent) -> bool {
        self.handle_confirm_key(key)
            || self.handle_budget_key(key)
            || self.handle_pending_plan_key(key)
    }

    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> bool {
        if self.advisory.pending_confirm.is_none() || !key.modifiers.is_empty() {
            return false;
        }
        let KeyCode::Char(ch) = key.code else {
            return false;
        };
        match ch {
            'y' => {
                self.resolve_confirm(true, false);
            }
            'Y' => {
                self.resolve_confirm(true, true);
            }
            'n' => {
                self.resolve_confirm(false, false);
            }
            'N' => {
                self.resolve_confirm(false, true);
            }
            _ => return false,
        }
        true
    }

    pub(super) fn handle_budget_key(&mut self, key: KeyEvent) -> bool {
        if !self.is_budget_halted() || !key.modifiers.is_empty() {
            return false;
        }
        let KeyCode::Char(ch) = key.code else {
            return false;
        };
        match ch.to_ascii_lowercase() {
            'c' => self.continue_past_budget(),
            'a' => self.abort_for_budget(),
            _ => return false,
        }
        true
    }

    pub(super) fn handle_pending_plan_key(&mut self, key: KeyEvent) -> bool {
        if self.pending_plan.is_none() || !self.input.is_empty() || !key.modifiers.is_empty() {
            return false;
        }
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => self.apply_pending_plan(),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.discard_pending_plan(),
            KeyCode::Char(' ') => self.toggle_plan_change_skip(),
            KeyCode::Char('j') | KeyCode::Down => self.move_plan_cursor(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_plan_cursor(-1),
            KeyCode::Char('g') => self.plan_cursor = 0,
            KeyCode::Char('G') => self.move_plan_cursor_to_end(),
            _ => return false,
        }
        true
    }

    pub(super) fn move_plan_cursor_to_end(&mut self) {
        let total = self.plan_change_count();
        if total > 0 {
            self.plan_cursor = total - 1;
        }
    }

    pub(super) fn update_quit_chord_arm(&mut self, key: KeyEvent) {
        if !is_quit_chord(key) {
            self.ctrl_c_armed_at = None;
        }
    }

    pub(super) fn handle_story_toggle_key(&mut self, key: KeyEvent) -> bool {
        if !key.modifiers.contains(KeyModifiers::CONTROL)
            || !matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
        {
            return false;
        }
        self.toggle_story_overlay();
        true
    }

    pub(super) fn reset_completion_cycle_for_key(&mut self, key: KeyEvent) {
        if !matches!(key.code, KeyCode::Tab) {
            self.reset_completion_cycle();
        }
    }

    pub(super) fn handle_control_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.ctrl {
            return false;
        }
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('d') => self.handle_quit_chord(),
            KeyCode::Char('a') => self.move_cursor_home(),
            KeyCode::Char('e') => self.move_cursor_end(),
            KeyCode::Char('b') => self.move_cursor_left(),
            KeyCode::Char('f') => self.move_cursor_right(),
            KeyCode::Char('w') => self.delete_word_left(),
            KeyCode::Char('u') => self.kill_to_start(),
            KeyCode::Char('k') => self.kill_to_end(),
            KeyCode::Char('h') => self.backspace(),
            KeyCode::Char('p') => self.history_prev(),
            KeyCode::Char('n') => self.history_next(),
            KeyCode::Char('l') => self.clear_conversation_preserving_input(),
            _ => return false,
        }
        true
    }
}
