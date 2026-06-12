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
        // First view-specific handler that claims the key wins; the hotkey
        // fallback is last so per-view keys take precedence.
        EMPTY_INPUT_VIEW_KEY_HANDLERS
            .iter()
            .any(|handler| handler(self, key, modifiers))
    }

    /// Arrow-key / single-key view hotkeys, tried after the per-view handlers.
    fn handle_view_hotkey_fallback(&mut self, key: KeyEvent, modifiers: KeyModifierState) -> bool {
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

    /// 3D playground controls (active only while `ShellView::Scene` is open and
    /// the prompt is empty): cycle scenes, pause, reset, and orbit by keyboard.
    pub(super) fn handle_scene_view_key(
        &mut self,
        key: KeyEvent,
        modifiers: KeyModifierState,
    ) -> bool {
        if !modifiers.plain || !matches!(self.shell_view, ShellView::Scene(_)) {
            return false;
        }
        // Gallery hotkeys yield to the prompt the moment the operator starts
        // typing — otherwise `back`/`home` are untypeable on the 3D page
        // (h/j/k/l would orbit the camera instead of reaching the prompt).
        if !self.input.is_empty() {
            return false;
        }
        // Orbit keys only apply on the 3D attack-surface page; on 2D pages they
        // fall through. Tab/space/r/Esc/q work on every page.
        let is_3d = matches!(self.shell_view, ShellView::Scene(page) if page.is_3d());
        match key.code {
            KeyCode::Tab | KeyCode::Char('n') => self.cycle_scene(1),
            KeyCode::BackTab | KeyCode::Char('N') => self.cycle_scene(-1),
            KeyCode::Char(' ') | KeyCode::Char('p') => self.scene_paused = !self.scene_paused,
            KeyCode::Char('r') => self.reset_scene_orientation(),
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
        let next = if direction >= 0 {
            self.scene_page.next()
        } else {
            self.scene_page.prev()
        };
        self.set_scene_page(next);
    }

    /// Manual orbit implies the operator wants to inspect a frame, so it pauses
    /// the idle spin; `space` resumes it.
    fn nudge_scene_yaw(&mut self, sign: f32) {
        self.scene_paused = true;
        self.scene_spin = super::ticking::wrap_angle(self.scene_spin + sign * SCENE_NUDGE);
    }

    fn nudge_scene_pitch(&mut self, sign: f32) {
        self.scene_paused = true;
        self.scene_pitch = (self.scene_pitch + sign * SCENE_NUDGE).clamp(-1.4, 1.4);
    }

    fn reset_scene_orientation(&mut self) {
        self.scene_spin = 0.6;
        self.scene_pitch = 0.45;
        self.scene_paused = false;
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

type ViewKeyHandler = fn(&mut ShellApp, KeyEvent, KeyModifierState) -> bool;

/// Per-view empty-prompt key handlers, tried in order; the hotkey fallback is
/// last so view-specific keys take precedence. Add a view by appending here.
const EMPTY_INPUT_VIEW_KEY_HANDLERS: &[ViewKeyHandler] = &[
    ShellApp::handle_config_view_key,
    ShellApp::handle_findings_view_key,
    ShellApp::handle_scene_view_key,
    ShellApp::handle_view_hotkey_fallback,
];

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
