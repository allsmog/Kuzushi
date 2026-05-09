use super::view_keybinding_helpers::{bind, bind_char};
use super::*;

pub(super) fn activity_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char('j', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollDown),
        bind_char('k', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollUp),
        bind_char('g', "j/k/g/G", "top", ViewHotkeyAction::ViewScrollTop),
        bind_char('G', "j/k/g/G", "bottom", ViewHotkeyAction::ViewScrollBottom),
        bind(
            HotkeyTrigger::Tab,
            "Tab",
            "toggle pane",
            ViewHotkeyAction::ActivityTabPaneFocus,
        ),
        bind_char(
            'V',
            "V",
            "verbose",
            ViewHotkeyAction::ActivityToggleVerbose,
        ),
        bind_char('p', "p", "pause", ViewHotkeyAction::ActivityTogglePause),
        bind_char('R', "R", "reset", ViewHotkeyAction::ActivityReset),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "focus task",
            ViewHotkeyAction::ActivityFocusSelected,
        ),
        bind_char(
            'c',
            "c",
            "cancel run",
            ViewHotkeyAction::ActivityCancelRunning,
        ),
        bind(
            HotkeyTrigger::Esc,
            "Esc",
            "cancel run",
            ViewHotkeyAction::ActivityCancelRunning,
        ),
    ]
}

pub(super) fn findings_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char('j', "j/k/g/G", "move", ViewHotkeyAction::FindingsNext),
        bind_char('k', "j/k/g/G", "move", ViewHotkeyAction::FindingsPrevious),
        bind_char('g', "j/k/g/G", "move", ViewHotkeyAction::FindingsFirst),
        bind_char('G', "j/k/g/G", "move", ViewHotkeyAction::FindingsLast),
        bind(
            HotkeyTrigger::PageDown,
            "PgUp/PgDn",
            "page",
            ViewHotkeyAction::FindingsPageDown,
        ),
        bind(
            HotkeyTrigger::PageUp,
            "PgUp/PgDn",
            "page",
            ViewHotkeyAction::FindingsPageUp,
        ),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "open",
            ViewHotkeyAction::FindingsOpen,
        ),
    ]
}

pub(super) fn threat_keybindings() -> Vec<ViewKeybinding> {
    [
        ('1', ThreatView::Dfd),
        ('2', ThreatView::Stride),
        ('3', ThreatView::Stories),
        ('4', ThreatView::Scope),
        ('5', ThreatView::Summary),
    ]
    .into_iter()
    .map(|(key, view)| {
        bind_char(
            key,
            "1..5",
            "switch threat view",
            ViewHotkeyAction::ThreatView(view),
        )
    })
    .collect()
}

pub(super) fn actor_detail_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char('f', "f", "filter", ViewHotkeyAction::ActorDetailFilterCycle),
        bind_char(
            '0',
            "0",
            "reset filter",
            ViewHotkeyAction::ActorDetailFilterReset,
        ),
        bind_char('j', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollDown),
        bind_char('k', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollUp),
        bind_char('g', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollTop),
        bind_char('G', "j/k/g/G", "scroll", ViewHotkeyAction::ViewScrollBottom),
    ]
}

pub(super) fn prompts_editor_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char('j', "j/k", "row", ViewHotkeyAction::PromptsCursorNext),
        bind_char('k', "j/k", "row", ViewHotkeyAction::PromptsCursorPrevious),
        bind(
            HotkeyTrigger::Down,
            "Up/Down",
            "row",
            ViewHotkeyAction::PromptsCursorNext,
        ),
        bind(
            HotkeyTrigger::Up,
            "Up/Down",
            "row",
            ViewHotkeyAction::PromptsCursorPrevious,
        ),
        bind_char(
            'e',
            "e/s/d/r",
            "edit",
            ViewHotkeyAction::PromptsAction(PromptsAction::Edit),
        ),
        bind_char(
            's',
            "e/s/d/r",
            "show",
            ViewHotkeyAction::PromptsAction(PromptsAction::Show),
        ),
        bind_char(
            'd',
            "e/s/d/r",
            "diff",
            ViewHotkeyAction::PromptsAction(PromptsAction::Diff),
        ),
        bind_char(
            'r',
            "e/s/d/r",
            "reset",
            ViewHotkeyAction::PromptsAction(PromptsAction::Reset),
        ),
        bind_char(
            'S',
            "S",
            "set",
            ViewHotkeyAction::PromptsAction(PromptsAction::Set),
        ),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "show",
            ViewHotkeyAction::PromptsAction(PromptsAction::Show),
        ),
    ]
}

pub(super) fn tune_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char('j', "j/k", "row", ViewHotkeyAction::TuneCursorNext),
        bind_char('k', "j/k", "row", ViewHotkeyAction::TuneCursorPrevious),
        bind(
            HotkeyTrigger::Down,
            "Up/Down",
            "row",
            ViewHotkeyAction::TuneCursorNext,
        ),
        bind(
            HotkeyTrigger::Up,
            "Up/Down",
            "row",
            ViewHotkeyAction::TuneCursorPrevious,
        ),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "activate",
            ViewHotkeyAction::TuneActivate,
        ),
    ]
}
