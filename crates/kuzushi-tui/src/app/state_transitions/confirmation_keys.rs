use super::*;

#[derive(Clone, Copy)]
pub(super) struct ConfirmKeyAction {
    pub(super) outcome: bool,
    pub(super) remember: bool,
}

pub(super) fn confirm_key_action(code: KeyCode) -> Option<ConfirmKeyAction> {
    if code == KeyCode::Esc {
        return Some(ConfirmKeyAction {
            outcome: false,
            remember: false,
        });
    }
    let KeyCode::Char(ch) = code else {
        return None;
    };
    CONFIRM_KEY_ACTIONS
        .iter()
        .find_map(|(candidate, action)| (*candidate == ch).then_some(*action))
}

const CONFIRM_KEY_ACTIONS: &[(char, ConfirmKeyAction)] = &[
    (
        'y',
        ConfirmKeyAction {
            outcome: true,
            remember: false,
        },
    ),
    (
        'Y',
        ConfirmKeyAction {
            outcome: true,
            remember: true,
        },
    ),
    (
        'n',
        ConfirmKeyAction {
            outcome: false,
            remember: false,
        },
    ),
    (
        'N',
        ConfirmKeyAction {
            outcome: false,
            remember: true,
        },
    ),
];

pub(super) fn confirm_key_is_consumed_without_action(code: KeyCode) -> bool {
    code == KeyCode::Enter
}

pub(super) fn confirm_key_modifiers_allowed(key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('Y') => HotkeyTrigger::Char('Y').matches(key),
        KeyCode::Char('N') => HotkeyTrigger::Char('N').matches(key),
        _ => key.modifiers.is_empty(),
    }
}
