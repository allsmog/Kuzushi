use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotkeyTrigger {
    Char(char),
    Enter,
    Tab,
    BackTab,
    Esc,
    PageUp,
    PageDown,
    Up,
    Down,
    Left,
    Right,
}

impl HotkeyTrigger {
    pub(crate) fn matches(self, key: KeyEvent) -> bool {
        // Allow SHIFT only when the trigger is an uppercase Char — terminals
        // typically deliver capital letters as `KeyCode::Char('R')` with
        // `KeyModifiers::SHIFT`. Other modifiers (Ctrl/Alt) always disqualify.
        let allowed = match (self, key.code) {
            (Self::Char(expected), KeyCode::Char(_)) if expected.is_ascii_uppercase() => {
                KeyModifiers::SHIFT | KeyModifiers::NONE
            }
            _ => KeyModifiers::NONE,
        };
        let leftover = key.modifiers - allowed;
        if !leftover.is_empty() {
            return false;
        }
        match (self, key.code) {
            (Self::Char(expected), KeyCode::Char(actual)) => expected == actual,
            (Self::Enter, KeyCode::Enter) => true,
            (Self::Tab, KeyCode::Tab) => true,
            (Self::BackTab, KeyCode::BackTab) => true,
            (Self::Esc, KeyCode::Esc) => true,
            (Self::PageUp, KeyCode::PageUp) => true,
            (Self::PageDown, KeyCode::PageDown) => true,
            (Self::Up, KeyCode::Up) => true,
            (Self::Down, KeyCode::Down) => true,
            (Self::Left, KeyCode::Left) => true,
            (Self::Right, KeyCode::Right) => true,
            _ => false,
        }
    }

    pub(crate) fn is_char(self) -> bool {
        matches!(self, Self::Char(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewHotkeyAction {
    CatalogActivate,
    WorkbenchCyclePane,
    WorkbenchCyclePanePrev,
    WorkbenchScrollNext,
    WorkbenchScrollPrev,
    WorkbenchScrollFirst,
    WorkbenchScrollLast,
    WorkbenchToggleCenter,
    WorkbenchCenterNext,
    WorkbenchCenterPrev,
    WorkbenchZoomCenter,
    WorkbenchTogglePaneZoom,
    WorkbenchOpen,
    WorkbenchPageNext,
    WorkbenchPagePrev,
    WorkbenchPage(WorkbenchPage),
    WorkbenchValidate,
    WorkbenchSuppress,
    WorkbenchOrderChain,
    WorkbenchCluster,
    RecommendCursorPrevious,
    RecommendCursorNext,
    RecommendScanComponent,
    RecommendPromoteComponent,
    ThreatView(ThreatView),
    ActorDetail(usize),
    PauseScan,
    ResumeScan,
    ViewScrollUp,
    ViewScrollDown,
    ViewScrollTop,
    ViewScrollBottom,
    ViewPageUp,
    ViewPageDown,
    Back,
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
    ActivityFocusSelected,
    ActivityDeckNext,
    ActivityDeckPrev,
    ActivityOpenDeckArtifact,
    ActivityOpenFindings,
    ActivityBackground,
    OpenNextPhase,
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
        // SHIFT alone does not disqualify a hotkey from firing — uppercase
        // letters arrive with `KeyModifiers::SHIFT` on most terminals, and
        // bind_char('R', ...) needs to match those.
        let only_shift_or_empty = (key.modifiers - KeyModifiers::SHIFT).is_empty();
        Self {
            ctrl,
            alt,
            plain: !ctrl && !alt,
            no_modifiers: only_shift_or_empty,
        }
    }

    pub(crate) fn ctrl_or_alt(self) -> bool {
        self.ctrl || self.alt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upper_char_matches_with_shift() {
        let trigger = HotkeyTrigger::Char('R');
        let key_no_mod = KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE);
        let key_shift = KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT);
        let key_ctrl = KeyEvent::new(KeyCode::Char('R'), KeyModifiers::CONTROL);
        assert!(
            trigger.matches(key_no_mod),
            "uppercase R no-mod should match"
        );
        assert!(
            trigger.matches(key_shift),
            "uppercase R with SHIFT should match"
        );
        assert!(
            !trigger.matches(key_ctrl),
            "uppercase R with CTRL should not match"
        );
    }

    #[test]
    fn lower_char_rejects_shift() {
        let trigger = HotkeyTrigger::Char('j');
        let key_no_mod = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE);
        let key_shift = KeyEvent::new(KeyCode::Char('j'), KeyModifiers::SHIFT);
        assert!(trigger.matches(key_no_mod));
        assert!(
            !trigger.matches(key_shift),
            "lowercase j with SHIFT means a different key"
        );
    }

    #[test]
    fn esc_and_tab_match() {
        assert!(HotkeyTrigger::Esc.matches(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(HotkeyTrigger::Tab.matches(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
    }

    #[test]
    fn modifier_state_treats_shift_as_no_modifiers() {
        let state = KeyModifierState::new(KeyEvent::new(KeyCode::Char('V'), KeyModifiers::SHIFT));
        assert!(
            state.no_modifiers,
            "uppercase V with SHIFT should be treated as plain so view hotkeys fire"
        );
    }
}
