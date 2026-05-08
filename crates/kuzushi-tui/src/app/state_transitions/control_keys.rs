use super::*;

pub(super) fn control_key_handler(code: KeyCode) -> Option<fn(&mut ShellApp)> {
    let KeyCode::Char(ch) = code else {
        return None;
    };
    CONTROL_KEY_ACTIONS
        .iter()
        .find_map(|(candidate, handler)| (*candidate == ch).then_some(*handler))
}

const CONTROL_KEY_ACTIONS: &[(char, fn(&mut ShellApp))] = &[
    ('c', ShellApp::handle_quit_chord),
    ('d', ShellApp::handle_quit_chord),
    ('a', ShellApp::move_cursor_home),
    ('e', ShellApp::move_cursor_end),
    ('b', ShellApp::move_cursor_left),
    ('f', ShellApp::move_cursor_right),
    ('w', ShellApp::delete_word_left),
    ('u', ShellApp::kill_to_start),
    ('k', ShellApp::kill_to_end),
    ('h', ShellApp::backspace),
    ('p', ShellApp::history_prev),
    ('n', ShellApp::history_next),
    ('l', ShellApp::clear_conversation_preserving_input),
];
