use super::view_keybinding_helpers::{bind, bind_char};
use super::*;

pub(super) fn catalog_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "load action",
            ViewHotkeyAction::CatalogActivate,
        ),
        bind_char(
            'e',
            "e",
            "expert engines",
            ViewHotkeyAction::CatalogToggleExpert,
        ),
    ]
}

pub(super) fn activity_keybindings() -> Vec<ViewKeybinding> {
    // j/k/g/G scroll comes from the shared `scroll_keybindings()` base.
    let mut bindings = vec![
        bind(
            HotkeyTrigger::Tab,
            "Tab",
            "toggle pane",
            ViewHotkeyAction::ActivityTabPaneFocus,
        ),
        bind(
            HotkeyTrigger::BackTab,
            "Shift+Tab",
            "toggle pane",
            ViewHotkeyAction::ActivityTabPaneFocus,
        ),
        bind_char('V', "V", "verbose", ViewHotkeyAction::ActivityToggleVerbose),
        bind_char(
            ' ',
            "Space",
            "feed pause",
            ViewHotkeyAction::ActivityTogglePause,
        ),
        bind_char('x', "x", "reset view", ViewHotkeyAction::ActivityReset),
        bind_char('b', "b", "background", ViewHotkeyAction::ActivityBackground),
    ];
    bindings.extend(activity_deck_keybindings());
    bindings.extend([bind(
        HotkeyTrigger::Enter,
        "Enter",
        "focus task",
        ViewHotkeyAction::ActivityFocusSelected,
    )]);
    bindings
}

fn activity_deck_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char(']', "[/]", "views", ViewHotkeyAction::ActivityDeckNext),
        bind_char('[', "[/]", "views", ViewHotkeyAction::ActivityDeckPrev),
        bind_char('f', "f", "findings", ViewHotkeyAction::ActivityOpenFindings),
        bind_char('o', "o", "open", ViewHotkeyAction::ActivityOpenDeckArtifact),
    ]
}

pub(super) fn home_keybindings() -> Vec<ViewKeybinding> {
    vec![bind_char(
        'n',
        "n",
        "next phase",
        ViewHotkeyAction::OpenNextPhase,
    )]
}

pub(super) fn recommend_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char(
            'j',
            "j/k",
            "component",
            ViewHotkeyAction::RecommendCursorNext,
        ),
        bind_char(
            'k',
            "j/k",
            "component",
            ViewHotkeyAction::RecommendCursorPrevious,
        ),
        bind(
            HotkeyTrigger::Down,
            "Up/Down",
            "component",
            ViewHotkeyAction::RecommendCursorNext,
        ),
        bind(
            HotkeyTrigger::Up,
            "Up/Down",
            "component",
            ViewHotkeyAction::RecommendCursorPrevious,
        ),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "scan component",
            ViewHotkeyAction::RecommendScanComponent,
        ),
        bind_char(
            'p',
            "p",
            "promote target",
            ViewHotkeyAction::RecommendPromoteComponent,
        ),
    ]
}

pub(super) fn workbench_keybindings(app: &ShellApp) -> Vec<ViewKeybinding> {
    // Keep the focused-pane controls first. The footer intentionally compacts
    // a long binding list on ordinary 80-column terminals, so ordering is a
    // discoverability contract: pane cycling, opening, and moving must survive
    // before page/visualization shortcuts and secondary actions.
    let page = crate::ui_view_models::active_workbench_page(app);
    let viewport = app.viewport();
    let interactive_panes = page.interactive_panes_for_viewport(
        app.router.workbench().center_mode(),
        viewport.columns,
        viewport.rows,
    );
    let mut bindings = workbench_pane_cycle_keybindings(interactive_panes);
    bindings.extend(workbench_open_keybindings(app, interactive_panes));
    bindings.extend(workbench_movement_keybindings());
    bindings.extend(workbench_page_keybindings());
    bindings.extend(workbench_zoom_keybindings());
    bindings.extend(workbench_center_keybindings());
    bindings.extend(workbench_secondary_action_keybindings(page));
    bindings.extend(workbench_return_keybindings(app));
    bindings
}

fn workbench_pane_cycle_keybindings(panes: &[WorkbenchPane]) -> Vec<ViewKeybinding> {
    if panes.len() <= 1 {
        return Vec::new();
    }
    [
        workbench_primary_pane_keybindings()[0],
        workbench_secondary_pane_keybindings()[0],
    ]
    .into()
}

fn workbench_open_keybindings(app: &ShellApp, panes: &[WorkbenchPane]) -> Vec<ViewKeybinding> {
    if app.router.workbench().focus() != WorkbenchPane::Findings
        || !panes.contains(&WorkbenchPane::Findings)
    {
        return Vec::new();
    }
    vec![workbench_open_keybinding()]
}

fn workbench_return_keybindings(app: &ShellApp) -> Vec<ViewKeybinding> {
    if app.router.workbench().focus() != WorkbenchPane::Details {
        return Vec::new();
    }
    vec![bind_char('q', "q", "review list", ViewHotkeyAction::Back)]
}

fn workbench_primary_pane_keybindings() -> [ViewKeybinding; 1] {
    [bind(
        HotkeyTrigger::Tab,
        "Tab",
        "pane",
        ViewHotkeyAction::WorkbenchCyclePane,
    )]
}

fn workbench_secondary_pane_keybindings() -> [ViewKeybinding; 1] {
    [bind(
        HotkeyTrigger::BackTab,
        "Shift+Tab",
        "pane back",
        ViewHotkeyAction::WorkbenchCyclePanePrev,
    )]
}

fn workbench_movement_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char(
            'j',
            "j/k/↑/↓",
            "move",
            ViewHotkeyAction::WorkbenchScrollNext,
        ),
        bind_char(
            'k',
            "j/k/↑/↓",
            "move",
            ViewHotkeyAction::WorkbenchScrollPrev,
        ),
        bind(
            HotkeyTrigger::Down,
            "j/k/↑/↓",
            "move",
            ViewHotkeyAction::WorkbenchScrollNext,
        ),
        bind(
            HotkeyTrigger::Up,
            "j/k/↑/↓",
            "move",
            ViewHotkeyAction::WorkbenchScrollPrev,
        ),
        bind_char('g', "g/G", "ends", ViewHotkeyAction::WorkbenchScrollFirst),
        bind_char('G', "g/G", "ends", ViewHotkeyAction::WorkbenchScrollLast),
    ]
}

fn workbench_center_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char(
            'd',
            "d",
            "CODE/DFD",
            ViewHotkeyAction::WorkbenchToggleCenter,
        ),
        bind(
            HotkeyTrigger::Right,
            "←/→",
            "center view",
            ViewHotkeyAction::WorkbenchCenterNext,
        ),
        bind(
            HotkeyTrigger::Left,
            "←/→",
            "center view",
            ViewHotkeyAction::WorkbenchCenterPrev,
        ),
        bind_char(
            ']',
            "[/]",
            "center view",
            ViewHotkeyAction::WorkbenchCenterNext,
        ),
        bind_char(
            '[',
            "[/]",
            "center view",
            ViewHotkeyAction::WorkbenchCenterPrev,
        ),
    ]
}

fn workbench_zoom_keybindings() -> [ViewKeybinding; 2] {
    [
        bind_char('Z', "Z", "zoom", ViewHotkeyAction::WorkbenchTogglePaneZoom),
        bind_char(
            'z',
            "z",
            "viz",
            ViewHotkeyAction::WorkbenchOpenFocusedVisualization,
        ),
    ]
}

fn workbench_page_keybindings() -> Vec<ViewKeybinding> {
    WorkbenchPage::ALL
        .iter()
        .enumerate()
        .map(|(index, page)| {
            bind_char(
                char::from_digit((index + 1) as u32, 10).unwrap(),
                "1..4",
                "page",
                ViewHotkeyAction::WorkbenchPage(*page),
            )
        })
        .collect()
}

fn workbench_open_keybinding() -> ViewKeybinding {
    bind(
        HotkeyTrigger::Enter,
        "Enter",
        "open",
        ViewHotkeyAction::WorkbenchOpen,
    )
}

fn workbench_secondary_action_keybindings(page: WorkbenchPage) -> Vec<ViewKeybinding> {
    let mut bindings = vec![
        bind_char('n', "n/N", "page", ViewHotkeyAction::WorkbenchPageNext),
        bind_char('N', "n/N", "page", ViewHotkeyAction::WorkbenchPagePrev),
    ];
    match page {
        WorkbenchPage::Review => bindings.extend([
            bind_char(
                'v',
                "v",
                "draft verify",
                ViewHotkeyAction::WorkbenchValidate,
            ),
            bind_char(
                'x',
                "x",
                "draft suppress",
                ViewHotkeyAction::WorkbenchSuppress,
            ),
            bind_char(
                'c',
                "c",
                "draft chain",
                ViewHotkeyAction::WorkbenchOrderChain,
            ),
        ]),
        WorkbenchPage::Coverage => bindings.push(bind_char(
            'D',
            "D",
            "cluster",
            ViewHotkeyAction::WorkbenchCluster,
        )),
        WorkbenchPage::Terrain | WorkbenchPage::Ship => {}
    }
    bindings
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
