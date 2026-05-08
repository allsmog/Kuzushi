use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotkeyTrigger {
    Char(char),
    Enter,
    PageUp,
    PageDown,
    Up,
    Down,
}

impl HotkeyTrigger {
    pub(crate) fn matches(self, key: KeyEvent) -> bool {
        if !key.modifiers.is_empty() {
            return false;
        }
        match (self, key.code) {
            (Self::Char(expected), KeyCode::Char(actual)) => expected == actual,
            (Self::Enter, KeyCode::Enter) => true,
            (Self::PageUp, KeyCode::PageUp) => true,
            (Self::PageDown, KeyCode::PageDown) => true,
            (Self::Up, KeyCode::Up) => true,
            (Self::Down, KeyCode::Down) => true,
            _ => false,
        }
    }

    pub(crate) fn is_char(self) -> bool {
        matches!(self, Self::Char(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewHotkeyAction {
    FindingsNext,
    FindingsPrevious,
    FindingsFirst,
    FindingsLast,
    FindingsPageDown,
    FindingsPageUp,
    FindingsOpen,
    ThreatView(ThreatView),
    ActorDetail(usize),
    PauseScan,
    ResumeScan,
    ViewScrollUp,
    ViewScrollDown,
    ViewScrollTop,
    ViewScrollBottom,
    TuneCursorPrevious,
    TuneCursorNext,
    TuneActivate,
    PromptsCursorPrevious,
    PromptsCursorNext,
    PromptsAction(PromptsAction),
    ActorDetailFilterCycle,
    ActorDetailFilterReset,
    ActivityTabPaneFocus,
    ActivityToggleVerbose,
    ActivityTogglePause,
    ActivityReset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ViewKeybinding {
    pub trigger: HotkeyTrigger,
    pub hint: &'static str,
    pub label: &'static str,
    pub action: ViewHotkeyAction,
}

impl ViewKeybinding {
    pub(crate) fn matches(self, key: KeyEvent) -> bool {
        self.trigger.matches(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyModifierState {
    pub(crate) ctrl: bool,
    pub(crate) alt: bool,
    pub(crate) plain: bool,
    pub(crate) no_modifiers: bool,
}

impl KeyModifierState {
    pub(crate) fn new(key: KeyEvent) -> Self {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        Self {
            ctrl,
            alt,
            plain: !ctrl && !alt,
            no_modifiers: key.modifiers.is_empty(),
        }
    }

    pub(crate) fn ctrl_or_alt(self) -> bool {
        self.ctrl || self.alt
    }
}
