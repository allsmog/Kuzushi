use super::*;

/// Canonical scroll set shared by every generically-scrollable view so the
/// footer always advertises the same `j/k/g/G` + paging keys. Views with a
/// bespoke cursor (Catalog, Findings) opt out and keep their own set.
pub(super) fn scroll_keybindings() -> Vec<ViewKeybinding> {
    // All four share the `scroll` label so the footer dedupes them into a
    // single `j/k/g/G scroll` hint (mirrors the Findings `move` grouping),
    // while the distinct actions still drive line/top/bottom behavior.
    vec![
        bind_char('j', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollDown),
        bind_char('k', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollUp),
        bind_char('g', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollTop),
        bind_char('G', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollBottom),
        bind(
            HotkeyTrigger::PageDown,
            "PgUp/PgDn",
            "scroll",
            ViewHotkeyAction::ViewPageDown,
        ),
        bind(
            HotkeyTrigger::PageUp,
            "PgUp/PgDn",
            "scroll",
            ViewHotkeyAction::ViewPageUp,
        ),
    ]
}

/// The universal "go back" affordance. Bound to Esc and shown in every
/// non-modal view's footer so a user is never stuck without an exit.
pub(super) fn back_keybinding() -> ViewKeybinding {
    bind(HotkeyTrigger::Esc, "Esc", "back", ViewHotkeyAction::Back)
}

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
    hint: impl Into<String>,
    label: impl Into<String>,
    action: ViewHotkeyAction,
) -> ViewKeybinding {
    ViewKeybinding {
        trigger,
        hint: hint.into(),
        label: label.into(),
        action,
    }
}
