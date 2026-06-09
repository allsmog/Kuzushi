use super::confirmation_keys::{confirm_key_action, ConfirmKeyAction};
use super::control_keys::control_key_handler;
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
        {}
    }

    pub(super) fn handle_modal_key(&mut self, key: KeyEvent) -> bool {
        self.handle_prereq_prompt_key(key)
            || self.handle_overlay_key(key)
            || self.handle_shared_modal_key(key)
    }

    /// Command palette and Ctrl+R reverse search both fully capture input while
    /// active. Checked before the normal key chain; Ctrl+C still falls through.
    fn handle_overlay_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.shell_view, ShellView::CommandPalette) {
            return self.handle_command_palette_key(key);
        }
        if self.history_search.is_some() {
            return self.handle_history_search_key(key);
        }
        false
    }

    /// Drive Ctrl+R reverse search. Enter accepts, Esc/Ctrl+C cancels, Ctrl+R
    /// steps to the next match, Backspace/printables edit the query.
    fn handle_history_search_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => self.cancel_history_search(),
            KeyCode::Char('c') if ctrl => self.cancel_history_search(),
            KeyCode::Char('r') if ctrl => self.history_search_next(),
            KeyCode::Enter => self.accept_history_search(),
            KeyCode::Backspace => self.history_search_backspace(),
            KeyCode::Char(ch) if !ctrl && !alt => self.history_search_input(ch),
            // Any navigation key accepts the match, then the keystroke is
            // re-dispatched normally (readline behavior).
            _ => {
                self.accept_history_search();
                return false;
            }
        }
        true
    }

    /// Drive the command palette while it is open. Ctrl+C falls through so the
    /// quit chord still works; everything else (typing, arrows, Enter, Esc) is
    /// consumed here.
    fn handle_command_palette_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Esc => self.close_palette(),
            KeyCode::Enter => self.accept_palette(),
            KeyCode::Up => self.palette_move(-1),
            KeyCode::Down => self.palette_move(1),
            KeyCode::Char('p') if ctrl => self.palette_move(-1),
            KeyCode::Char('n') if ctrl => self.palette_move(1),
            KeyCode::Char('g') if ctrl => self.close_palette(),
            KeyCode::Char('c') if ctrl => return false,
            KeyCode::Backspace => self.palette_backspace(),
            KeyCode::Char(ch) if !ctrl && !alt => self.palette_input(ch),
            _ => return false,
        }
        true
    }

    fn handle_shared_modal_key(&mut self, key: KeyEvent) -> bool {
        self.handle_confirm_key(key)
            || self.handle_retry_key(key)
            || self.handle_budget_key(key)
            || self.handle_pending_plan_key(key)
            || self.handle_picker_key(key)
            || self.handle_notice_dismiss_key(key)
    }

    /// The end-of-engagement retry gate: `y`/Enter retries the failed tasks
    /// (with auto-adjustments), `n`/Esc skips them.
    fn handle_retry_key(&mut self, key: KeyEvent) -> bool {
        if self.advisory.pending_retry.is_none() || !key.modifiers.is_empty() {
            return false;
        }
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                self.retry_failed_tasks();
                true
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.decline_retry();
                true
            }
            _ => false,
        }
    }

    /// Esc dismisses a visible notice banner. Returns false when no notice is
    /// present so Esc falls through to view-back / draft-restore as usual.
    fn handle_notice_dismiss_key(&mut self, key: KeyEvent) -> bool {
        if self.advisory.notice.is_none() || key.code != KeyCode::Esc || !key.modifiers.is_empty() {
            return false;
        }
        self.clear_notice();
        true
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
