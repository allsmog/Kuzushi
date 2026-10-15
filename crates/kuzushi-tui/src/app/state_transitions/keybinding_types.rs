use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotkeyTrigger {
    Char(char),
    ControlChar(char),
    Enter,
    Tab,
    BackTab,
    Esc,
    PageUp,
    PageDown,
    End,
    Up,
    Down,
    Never,
}

impl HotkeyTrigger {
    pub(crate) fn matches(self, key: KeyEvent) -> bool {
        if let Self::ControlChar(expected) = self {
            return key.code == KeyCode::Char(expected) && key.modifiers == KeyModifiers::CONTROL;
        }
        // Allow SHIFT only when the trigger is an uppercase Char — terminals
        // typically deliver capital letters as `KeyCode::Char('R')` with
        // `KeyModifiers::SHIFT`. Other modifiers (Ctrl/Alt) always disqualify.
        let allowed = match (self, key.code) {
            (Self::Char(expected), KeyCode::Char(_)) if expected.is_ascii_uppercase() => {
                KeyModifiers::SHIFT | KeyModifiers::NONE
            }
            // Crossterm reports the terminal BackTab sequence (ESC [ Z) as
            // `KeyCode::BackTab` with SHIFT set. Treat that as the canonical
            // Shift+Tab event while retaining the modifier-free form used by
            // a few terminal/test backends.
            (Self::BackTab, KeyCode::BackTab) => KeyModifiers::SHIFT | KeyModifiers::NONE,
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
            (Self::End, KeyCode::End) => true,
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
    RelationshipsOpen,
    LessonsOpen,
    GoalReviewOpen,
    FindingGroupsOpen,
    RelationshipNext,
    RelationshipPrevious,
    RelationshipAccept,
    RelationshipToggleSelection,
    RelationshipSelectPage,
    RelationshipClearSelection,
    RelationshipReviewSelection,
    RelationshipReject,
    RelationshipRemove,
    RelationshipsRefresh,
    RelationshipsNextPage,
    RelationshipsPreviousPage,
    CatalogActivate,
    CatalogToggleExpert,
    CatalogRefreshDependencies,
    WorkbenchCyclePane,
    WorkbenchCyclePanePrev,
    WorkbenchScrollNext,
    WorkbenchScrollPrev,
    WorkbenchScrollFirst,
    WorkbenchScrollLast,
    WorkbenchOpenFocusedVisualization,
    WorkbenchTogglePaneZoom,
    WorkbenchOpen,
    WorkbenchPageNext,
    WorkbenchPlanStudy,
    WorkbenchReport,
    WorkbenchPagePrev,
    WorkbenchPage(WorkbenchPage),
    WorkbenchValidate,
    WorkbenchInvestigationBoundary,
    WorkbenchDeferProof,
    WorkbenchReverifyPatch,
    WorkbenchSuppress,
    WorkbenchInvariantHunt,
    WorkbenchOrderChain,
    WorkbenchChainFold,
    WorkbenchTraceView,
    WorkbenchCluster,
    WorkbenchBacklogToggle,
    /// `/` on Review: open the incremental findings search capture.
    WorkbenchReviewSearch,
    WorkbenchReviewLedgerFilter,
    WorkbenchFindingsPageNext,
    WorkbenchFindingsPagePrevious,
    WorkbenchCompareObservations,
    WorkbenchReviewCurrentSource,
    /// `/` on Logs: open the incremental transcript filter capture.
    LogsFilter,
    RunDiffToggleSources,
    /// One-key backlog decision; payload is the review verdict keyword fed
    /// through the ordinary `decision <verdict> <reason>` path.
    WorkbenchBacklogDecide(&'static str),
    WorkbenchBacklogSeverityCycle,
    WorkbenchBacklogToolCycle,
    WorkbenchBacklogBulkDefer,
    WorkbenchBacklogUndo,
    RecommendCursorPrevious,
    RecommendCursorNext,
    RecommendScanComponent,
    RecommendPromoteComponent,
    RecommendRefresh,
    ThreatView(ThreatView),
    ThreatModelNext,
    ThreatModelPrevious,
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
    ActivityBackground,
    ActivitySteer,
    OpenNextPhase,
    OpenCommandPalette,
    OpenHelp,
    EnterNavigateMode,
    EnterPromptMode,
    CompleteComposer,
    PhaseResult(PhaseResultCommand),
    QuestionSubmit,
    QuestionCancel,
    QuestionBackground,
    QuestionNextOption,
    QuestionPreviousOption,
    QuestionNext,
    QuestionPrevious,
    QuestionOther,
    CampaignCursorPrevious,
    CampaignCursorNext,
    CampaignOpenDetail,
    CampaignBackToList,
    CampaignToggleExclude,
    CampaignCycleWorkers,
    CampaignLaunch,
    CampaignReviewStudy,
    CampaignKill,
    CampaignShowPrompt,
    CampaignRefresh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewKeybinding {
    pub trigger: HotkeyTrigger,
    pub hint: String,
    pub label: String,
    pub action: ViewHotkeyAction,
}

impl ViewKeybinding {
    pub(crate) fn matches(&self, key: KeyEvent) -> bool {
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
    fn backtab_accepts_the_crossterm_shift_modifier() {
        let trigger = HotkeyTrigger::BackTab;
        assert!(trigger.matches(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)));
        assert!(trigger.matches(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)));
        assert!(!trigger.matches(KeyEvent::new(KeyCode::BackTab, KeyModifiers::ALT)));
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
