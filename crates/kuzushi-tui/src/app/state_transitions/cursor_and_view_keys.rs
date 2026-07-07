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
    ) -> InputUpdate {
        if !self.input().is_empty() {
            return InputUpdate::ignored();
        }
        // First view-specific handler that claims the key wins; the hotkey
        // fallback is last so per-view keys take precedence.
        let config_update = self.handle_config_view_key(key, modifiers);
        if config_update.handled {
            return config_update;
        }
        if self.handle_scene_view_key(key, modifiers) {
            return InputUpdate::handled();
        }
        self.handle_view_hotkey_fallback(key, modifiers)
    }

    /// Arrow-key / single-key view hotkeys, tried after the per-view handlers.
    fn handle_view_hotkey_fallback(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if matches!(key.code, KeyCode::Up | KeyCode::Down) && modifiers.plain {
            let update = self.handle_view_hotkey(key);
            if update.handled {
                return update;
            }
        }
        if modifiers.no_modifiers {
            return self.handle_view_hotkey(key);
        }
        InputUpdate::ignored()
    }

    pub(super) fn handle_config_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> InputUpdate {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Config) {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Up => {
                self.move_model_selection(-1);
                InputUpdate::handled()
            }
            KeyCode::Down => {
                self.move_model_selection(1);
                InputUpdate::handled()
            }
            KeyCode::Enter => InputUpdate::handled_with_effects(self.select_current_model_choice()),
            _ => InputUpdate::ignored(),
        }
    }

    /// 3D playground controls (active only while `ShellView::Scene` is open and
    /// the prompt is empty): cycle scenes, pause, reset, and orbit by keyboard.
    pub(super) fn handle_scene_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Scene) {
            return false;
        }
        // Gallery hotkeys yield to the prompt the moment the operator starts
        // typing — otherwise `back`/`home` are untypeable on the 3D page
        // (h/j/k/l would orbit the camera instead of reaching the prompt).
        if !self.input().is_empty() {
            return false;
        }
        // 3D controls only apply on the attack-surface page; on 2D pages they
        // fall through. Tab/Shift+Tab/Esc/q work on every page.
        let is_3d = self.router.scene().page().is_3d();
        match key.code {
            KeyCode::Tab => self.cycle_scene(1),
            KeyCode::BackTab => self.cycle_scene(-1),
            KeyCode::Char(' ') | KeyCode::Char('p') if is_3d => {
                self.router.scene_mut().toggle_paused()
            }
            KeyCode::Char('r') if is_3d => self.reset_scene_orientation(),
            // Explicit exits: the gallery is a leaf view, never a trap.
            KeyCode::Esc | KeyCode::Char('q') => self.go_back(),
            KeyCode::Char('h') if is_3d => self.nudge_scene_yaw(-1.0),
            KeyCode::Char('l') if is_3d => self.nudge_scene_yaw(1.0),
            KeyCode::Char('k') if is_3d => self.nudge_scene_pitch(1.0),
            KeyCode::Char('j') if is_3d => self.nudge_scene_pitch(-1.0),
            _ => return false,
        }
        true
    }

    fn cycle_scene(&mut self, direction: i32) {
        let next = self.router.scene_mut().next_page(direction);
        self.set_scene_page(next);
    }

    /// Manual orbit implies the operator wants to inspect a frame, so it pauses
    /// the idle spin; `space` resumes it.
    fn nudge_scene_yaw(&mut self, sign: f32) {
        self.router.scene_mut().nudge_yaw(sign * SCENE_NUDGE);
    }

    fn nudge_scene_pitch(&mut self, sign: f32) {
        self.router.scene_mut().nudge_pitch(sign * SCENE_NUDGE);
    }

    fn reset_scene_orientation(&mut self) {
        self.router.scene_mut().reset_orientation();
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
