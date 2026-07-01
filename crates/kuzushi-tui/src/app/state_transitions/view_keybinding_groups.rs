use super::view_keybinding_helpers::{bind, bind_char};
use super::*;

pub(super) fn activity_keybindings() -> Vec<ViewKeybinding> {
    // j/k/g/G scroll comes from the shared `scroll_keybindings()` base.
    let mut bindings = vec![
        bind(
            HotkeyTrigger::Tab,
            "Tab",
            "toggle pane",
            ViewHotkeyAction::ActivityTabPaneFocus,
        ),
        bind_char('V', "V", "verbose", ViewHotkeyAction::ActivityToggleVerbose),
        bind_char(
            'p',
            "p",
            "feed pause",
            ViewHotkeyAction::ActivityTogglePause,
        ),
        bind_char('R', "R", "reset", ViewHotkeyAction::ActivityReset),
    ];
    bindings.extend(activity_deck_keybindings());
    bindings.extend([
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "focus task",
            ViewHotkeyAction::ActivityFocusSelected,
        ),
        bind_char(
            'C',
            "C",
            "arm cancel",
            ViewHotkeyAction::ActivityCancelRunning,
        ),
    ]);
    bindings
}

fn activity_deck_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind(
            HotkeyTrigger::Right,
            "←/→",
            "views",
            ViewHotkeyAction::ActivityDeckNext,
        ),
        bind(
            HotkeyTrigger::Left,
            "←/→",
            "views",
            ViewHotkeyAction::ActivityDeckPrev,
        ),
        bind_char(']', "←/→", "views", ViewHotkeyAction::ActivityDeckNext),
        bind_char('[', "←/→", "views", ViewHotkeyAction::ActivityDeckPrev),
        bind_char('f', "f", "findings", ViewHotkeyAction::ActivityOpenFindings),
        bind_char('o', "o", "open", ViewHotkeyAction::ActivityOpenDeckArtifact),
    ]
}

pub(super) fn workbench_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind(
            HotkeyTrigger::Tab,
            "Tab",
            "cycle pane",
            ViewHotkeyAction::WorkbenchCyclePane,
        ),
        bind_char('j', "j/k", "move", ViewHotkeyAction::WorkbenchScrollNext),
        bind_char('k', "j/k", "move", ViewHotkeyAction::WorkbenchScrollPrev),
        bind_char('g', "g/G", "ends", ViewHotkeyAction::WorkbenchScrollFirst),
        bind_char('G', "g/G", "ends", ViewHotkeyAction::WorkbenchScrollLast),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "open finding",
            ViewHotkeyAction::WorkbenchOpen,
        ),
        bind(
            HotkeyTrigger::BackTab,
            "Shift+Tab",
            "cycle pane",
            ViewHotkeyAction::WorkbenchCyclePanePrev,
        ),
    ]
}

pub(super) fn threat_keybindings() -> Vec<ViewKeybinding> {
    [
        ('1', ThreatView::Stride),
        ('2', ThreatView::Stories),
        ('3', ThreatView::Scope),
        ('4', ThreatView::Summary),
    ]
    .into_iter()
    .map(|(key, view)| {
        bind_char(
            key,
            "1..4",
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
        // j/k/g/G scroll comes from the shared `scroll_keybindings()` base.
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
