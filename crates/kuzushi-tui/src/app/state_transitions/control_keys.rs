use super::*;

#[derive(Clone, Copy)]
pub(super) enum ControlKeyAction {
    QuitChord,
    Edit(fn(&mut ShellApp)),
}

impl ControlKeyAction {
    pub(super) fn apply(self, app: &mut ShellApp) -> InputUpdate {
        match self {
            Self::QuitChord => app.reduce_quit_chord(),
            Self::Edit(handler) => {
                handler(app);
                InputUpdate::handled()
            }
        }
    }
}

pub(super) fn control_key_action(code: KeyCode) -> Option<ControlKeyAction> {
    let KeyCode::Char(ch) = code else {
        return None;
    };
    CONTROL_KEY_ACTIONS
        .iter()
        .find_map(|(candidate, action)| (*candidate == ch).then_some(*action))
}

const CONTROL_KEY_ACTIONS: &[(char, ControlKeyAction)] = &[
    ('c', ControlKeyAction::QuitChord),
    ('d', ControlKeyAction::QuitChord),
    ('a', ControlKeyAction::Edit(ShellApp::move_cursor_home)),
    ('e', ControlKeyAction::Edit(ShellApp::move_cursor_end)),
    ('b', ControlKeyAction::Edit(ShellApp::move_cursor_left)),
    ('f', ControlKeyAction::Edit(ShellApp::move_cursor_right)),
    ('w', ControlKeyAction::Edit(ShellApp::delete_word_left)),
    ('u', ControlKeyAction::Edit(ShellApp::kill_to_start)),
    ('k', ControlKeyAction::Edit(ShellApp::kill_to_end)),
    ('h', ControlKeyAction::Edit(ShellApp::backspace)),
    ('p', ControlKeyAction::Edit(ShellApp::history_prev)),
    ('n', ControlKeyAction::Edit(ShellApp::history_next)),
    (
        'l',
        ControlKeyAction::Edit(ShellApp::clear_conversation_preserving_input),
    ),
    ('r', ControlKeyAction::Edit(ShellApp::enter_history_search)),
    (
        '_',
        ControlKeyAction::Edit(ShellApp::restore_last_cleared_input),
    ),
    (
        '/',
        ControlKeyAction::Edit(ShellApp::restore_last_cleared_input),
    ),
    // Ctrl+K is kill-to-end, so the palette uses Ctrl+G ("go to command").
    ('g', ControlKeyAction::Edit(ShellApp::open_command_palette)),
];
