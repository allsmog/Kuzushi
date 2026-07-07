use super::*;

impl ShellApp {
    pub(super) fn handle_pending_plan_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !pending_plan_key_is_active(
            self.engagement.has_pending_plan(),
            self.input().is_empty(),
            key.modifiers.is_empty(),
        ) {
            return InputUpdate::ignored();
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                InputUpdate::handled_with_effects(self.reduce_apply_pending_plan())
            }
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                InputUpdate::handled_with_effects(self.reduce_discard_pending_plan())
            }
            _ => pending_plan_key_handler(key.code).map_or_else(InputUpdate::ignored, |handler| {
                handler(self);
                InputUpdate::handled()
            }),
        }
    }

    fn move_plan_cursor_down_key(&mut self) {
        self.move_plan_cursor(1);
    }

    fn move_plan_cursor_up_key(&mut self) {
        self.move_plan_cursor(-1);
    }

    fn move_plan_cursor_to_start(&mut self) {
        self.engagement.move_plan_cursor_to_start();
    }

    pub(super) fn move_plan_cursor_to_end(&mut self) {
        self.engagement.move_plan_cursor_to_end();
    }
}

pub(super) fn pending_plan_key_handler(code: KeyCode) -> Option<fn(&mut ShellApp)> {
    PENDING_PLAN_KEY_ACTIONS
        .iter()
        .find_map(|(candidate, handler)| (*candidate == code).then_some(*handler))
}

fn pending_plan_key_is_active(
    has_pending_plan: bool,
    input_is_empty: bool,
    modifiers_are_empty: bool,
) -> bool {
    has_pending_plan && input_is_empty && modifiers_are_empty
}

const PENDING_PLAN_KEY_ACTIONS: &[(KeyCode, fn(&mut ShellApp))] = &[
    (KeyCode::Char(' '), ShellApp::toggle_plan_change_skip),
    (KeyCode::Char('j'), ShellApp::move_plan_cursor_down_key),
    (KeyCode::Down, ShellApp::move_plan_cursor_down_key),
    (KeyCode::Char('k'), ShellApp::move_plan_cursor_up_key),
    (KeyCode::Up, ShellApp::move_plan_cursor_up_key),
    (KeyCode::Char('g'), ShellApp::move_plan_cursor_to_start),
    (KeyCode::Char('G'), ShellApp::move_plan_cursor_to_end),
];
