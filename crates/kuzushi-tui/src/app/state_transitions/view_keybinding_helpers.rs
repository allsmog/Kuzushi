use super::*;

pub(super) fn pause_scan_keybindings() -> [ViewKeybinding; 2] {
    [
        bind_char('p', "p", "pause", ViewHotkeyAction::PauseScan),
        bind_char('P', "p", "pause", ViewHotkeyAction::PauseScan),
    ]
}

pub(super) fn resume_scan_keybindings() -> [ViewKeybinding; 2] {
    [
        bind_char('r', "r", "resume", ViewHotkeyAction::ResumeScan),
        bind_char('R', "r", "resume", ViewHotkeyAction::ResumeScan),
    ]
}

pub(super) fn bind_char(
    key: char,
    hint: &'static str,
    label: &'static str,
    action: ViewHotkeyAction,
) -> ViewKeybinding {
    bind(HotkeyTrigger::Char(key), hint, label, action)
}

pub(super) fn bind(
    trigger: HotkeyTrigger,
    hint: &'static str,
    label: &'static str,
    action: ViewHotkeyAction,
) -> ViewKeybinding {
    ViewKeybinding {
        trigger,
        hint,
        label,
        action,
    }
}
