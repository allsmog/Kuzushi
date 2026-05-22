use super::confirmation_keys::{confirm_key_action, ConfirmKeyAction};
use super::control_keys::control_key_handler;
use super::pending_plan_keys::pending_plan_key_handler;
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
        self.handle_prereq_prompt_key(key) || self.handle_shared_modal_key(key)
    }

    fn handle_shared_modal_key(&mut self, key: KeyEvent) -> bool {
        self.handle_confirm_key(key)
            || self.handle_budget_key(key)
            || self.handle_pending_plan_key(key)
            || self.handle_picker_key(key)
    }

    pub(super) fn handle_confirm_key(&mut self, key: KeyEvent) -> bool {
        if !self.confirm_key_ready(key) {
            return false;
        }
        let Some(action) = confirm_key_action(key.code) else {
            return false;
        };
        self.apply_confirm_key_action(action);
        true
    }

    fn confirm_key_ready(&self, key: KeyEvent) -> bool {
        self.advisory.pending_confirm.is_some() && key.modifiers.is_empty()
    }

    fn apply_confirm_key_action(&mut self, action: ConfirmKeyAction) {
        self.resolve_confirm(action.outcome, action.remember);
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
        let Some(handler) = control_key_handler(key.code) else {
            return false;
        };
        handler(self);
        true
    }
}
