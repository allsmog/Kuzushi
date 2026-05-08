use super::*;

#[derive(Clone, Copy)]
pub(super) struct ConfirmKeyAction {
    pub(super) outcome: bool,
    pub(super) remember: bool,
}

pub(super) fn confirm_key_action(code: KeyCode) -> Option<ConfirmKeyAction> {
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
