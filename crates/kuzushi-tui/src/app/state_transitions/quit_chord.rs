use super::*;

pub(crate) fn is_quit_chord(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'))
}

pub(crate) fn is_activity_cancel_key(key: KeyEvent) -> bool {
    let allowed = KeyModifiers::SHIFT | KeyModifiers::NONE;
    (key.modifiers - allowed).is_empty() && matches!(key.code, KeyCode::Char('C'))
}
