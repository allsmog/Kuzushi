use super::view_keybinding_helpers::{bind, bind_char};
use super::*;

pub(super) fn campaign_keybindings() -> Vec<ViewKeybinding> {
    let mut bindings = vec![
        bind_char(
            'k',
            "j/k",
            "cursor",
            ViewHotkeyAction::CampaignCursorPrevious,
        ),
        bind_char('j', "j/k", "cursor", ViewHotkeyAction::CampaignCursorNext),
        bind(
            HotkeyTrigger::Up,
            "↑/↓",
            "cursor",
            ViewHotkeyAction::CampaignCursorPrevious,
        ),
        bind(
            HotkeyTrigger::Down,
            "↑/↓",
            "cursor",
            ViewHotkeyAction::CampaignCursorNext,
        ),
        bind(
            HotkeyTrigger::Enter,
            "Enter",
            "open jobs",
            ViewHotkeyAction::CampaignOpenDetail,
        ),
        bind_char(
            'q',
            "q",
            "campaign list",
            ViewHotkeyAction::CampaignBackToList,
        ),
    ];
    bindings.extend([
        bind_char(
            'x',
            "x",
            "include/exclude",
            ViewHotkeyAction::CampaignToggleExclude,
        ),
        bind_char('w', "w", "workers", ViewHotkeyAction::CampaignCycleWorkers),
        bind_char('L', "L", "launch", ViewHotkeyAction::CampaignLaunch),
        bind_char('K', "K", "kill dispatcher", ViewHotkeyAction::CampaignKill),
        bind_char('e', "e", "prompt", ViewHotkeyAction::CampaignShowPrompt),
        bind_char('r', "r", "refresh", ViewHotkeyAction::CampaignRefresh),
    ]);
    bindings
}

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
    // Line/edge scrolling comes from the shared `scroll_keybindings()` base.
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
        bind_char('s', "s", "steer", ViewHotkeyAction::ActivitySteer),
    ];
    bindings.extend([bind(
        HotkeyTrigger::Enter,
        "Enter",
        "focus task",
        ViewHotkeyAction::ActivityFocusSelected,
    )]);
    bindings
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
    let plan = workbench_phase_plan(app);
    workbench_keybindings_for_plan(app, plan.as_ref())
}

pub(super) fn workbench_keybindings_for_plan(
    app: &ShellApp,
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) -> Vec<ViewKeybinding> {
    // Keep the focused-pane controls first. The footer intentionally compacts
    // a long binding list on ordinary 80-column terminals, so ordering is a
    // discoverability contract: pane cycling, opening, and moving must survive
    // before page/visualization shortcuts and secondary actions.
    let page = crate::ui_view_models::active_workbench_page(app);
    if plan.is_some_and(|plan| plan.density == crate::ui_view_models::LayoutDensity::Guided) {
        // A guided QUESTION card owns every key. A RESULT checkpoint only
        // owns the keys its strip binds (dispatched before these): page
        // navigation and page-level actions must keep working under an
        // unresolved result, or the operator is stranded on the phase page.
        if app.guided_scan_question_is_open() {
            return Vec::new();
        }
        let mut bindings = workbench_page_keybindings();
        bindings.extend(workbench_secondary_action_keybindings(
            page,
            crate::ui_view_models::review_backlog_active(app),
        ));
        return bindings;
    }
    let available_count = plan.map_or(0, |plan| plan.available_surfaces.len());
    let focused_surface = plan
        .and_then(|plan| plan.surface(plan.effective_focus))
        .copied();
    let interaction = focused_surface.map(|surface| surface.interaction);
    let mut bindings = workbench_pane_cycle_keybindings(available_count);
    bindings.extend(workbench_open_keybindings(focused_surface));
    if matches!(
        interaction,
        Some(
            crate::ui_view_models::SurfaceInteraction::Selectable
                | crate::ui_view_models::SurfaceInteraction::Scrollable
        )
    ) {
        bindings.extend(workbench_movement_keybindings());
    }
    bindings.extend(workbench_page_keybindings());
    if !plan.is_some_and(|plan| plan.density == crate::ui_view_models::LayoutDensity::Guided) {
        bindings.extend(workbench_zoom_keybindings());
    }
    bindings.extend(workbench_secondary_action_keybindings(
        page,
        crate::ui_view_models::review_backlog_active(app),
    ));
    bindings.extend(workbench_return_keybindings(plan));
    bindings
}

fn workbench_pane_cycle_keybindings(available_count: usize) -> Vec<ViewKeybinding> {
    if available_count <= 1 {
        return Vec::new();
    }
    [
        workbench_primary_pane_keybindings()[0].clone(),
        workbench_previous_pane_keybindings()[0].clone(),
        workbench_next_pane_keybindings()[0].clone(),
    ]
    .into()
}

fn workbench_open_keybindings(
    surface: Option<crate::ui_view_models::PlannedPhaseSurface>,
) -> Vec<ViewKeybinding> {
    let can_open = surface.is_some_and(|surface| {
        surface.interaction == crate::ui_view_models::SurfaceInteraction::Selectable
            || surface.id == crate::ui_view_models::PhaseSurfaceId::ReviewQueue
    });
    if !can_open {
        return Vec::new();
    }
    vec![workbench_open_keybinding()]
}

fn workbench_phase_plan(app: &ShellApp) -> Option<crate::ui_view_models::PhasePresentationPlan> {
    let viewport = app.viewport();
    crate::renderer::workbench_phase_plan_for_app(
        app,
        ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
    )
}

fn workbench_return_keybindings(
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) -> Vec<ViewKeybinding> {
    let is_review_detail = plan.is_some_and(|plan| {
        plan.effective_focus == crate::ui_view_models::PhaseSurfaceId::ReviewDetail
    });
    if !is_review_detail {
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

fn workbench_previous_pane_keybindings() -> [ViewKeybinding; 1] {
    [bind_char(
        '[',
        "[",
        "pane back",
        ViewHotkeyAction::WorkbenchCyclePanePrev,
    )]
}

fn workbench_next_pane_keybindings() -> [ViewKeybinding; 1] {
    [bind_char(
        ']',
        "]",
        "pane",
        ViewHotkeyAction::WorkbenchCyclePane,
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
                "1..5",
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

fn workbench_secondary_action_keybindings(
    page: WorkbenchPage,
    backlog: bool,
) -> Vec<ViewKeybinding> {
    let mut bindings = workbench_page_navigation_keybindings();
    bindings.extend(workbench_page_action_keybindings(page, backlog));
    bindings
}

fn workbench_page_navigation_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind(
            HotkeyTrigger::BackTab,
            "Shift+Tab",
            "next phase",
            ViewHotkeyAction::WorkbenchPageNext,
        ),
        bind_char('n', "n/N", "page", ViewHotkeyAction::WorkbenchPageNext),
        bind_char('N', "n/N", "page", ViewHotkeyAction::WorkbenchPagePrev),
    ]
}

fn workbench_page_action_keybindings(page: WorkbenchPage, backlog: bool) -> Vec<ViewKeybinding> {
    match page {
        WorkbenchPage::Prove => prove_page_action_keybindings(),
        WorkbenchPage::Review => review_page_action_keybindings(backlog),
        WorkbenchPage::Fix => vec![bind_char(
            'v',
            "v",
            "reverify applied",
            ViewHotkeyAction::WorkbenchReverifyPatch,
        )],
        WorkbenchPage::Map | WorkbenchPage::Scan => Vec::new(),
    }
}

/// The backlog preset arms one-key decisions; they are bound (and shown in
/// the footer) only while the preset is active so ordinary Review browsing
/// cannot record a decision by a stray keypress.
fn review_page_action_keybindings(backlog: bool) -> Vec<ViewKeybinding> {
    let mut bindings = vec![
        bind_char('D', "D", "cluster", ViewHotkeyAction::WorkbenchCluster),
        bind_char('C', "C", "chains", ViewHotkeyAction::WorkbenchChainFold),
        bind_char(
            'i',
            "i",
            "invariant hunt",
            ViewHotkeyAction::WorkbenchInvariantHunt,
        ),
        bind_char(
            'B',
            "B",
            if backlog { "backlog off" } else { "backlog" },
            ViewHotkeyAction::WorkbenchBacklogToggle,
        ),
        bind_char(
            '/',
            "/",
            "search findings",
            ViewHotkeyAction::WorkbenchReviewSearch,
        ),
    ];
    // `1..5` are the page-switch keys, so decisions use mnemonic letters.
    if backlog {
        bindings.extend(backlog_decision_keybindings());
    }
    bindings
}

fn backlog_decision_keybindings() -> Vec<ViewKeybinding> {
    let mut bindings = backlog_verdict_keybindings();
    bindings.extend([
        bind_char(
            's',
            "s",
            "sev filter",
            ViewHotkeyAction::WorkbenchBacklogSeverityCycle,
        ),
        bind_char(
            't',
            "t",
            "tool filter",
            ViewHotkeyAction::WorkbenchBacklogToolCycle,
        ),
        bind_char(
            'X',
            "X",
            "defer-all",
            ViewHotkeyAction::WorkbenchBacklogBulkDefer,
        ),
        bind_char('u', "u", "undo", ViewHotkeyAction::WorkbenchBacklogUndo),
    ]);
    bindings
}

fn backlog_verdict_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char(
            'c',
            "c",
            "confirm",
            ViewHotkeyAction::WorkbenchBacklogDecide("confirmed"),
        ),
        bind_char(
            'f',
            "f",
            "reject-FP",
            ViewHotkeyAction::WorkbenchBacklogDecide("rejected_false_positive"),
        ),
        bind_char(
            'd',
            "d",
            "defer",
            ViewHotkeyAction::WorkbenchBacklogDecide("deferred"),
        ),
        bind_char(
            'w',
            "w",
            "needs-review",
            ViewHotkeyAction::WorkbenchBacklogDecide("needs_review"),
        ),
    ]
}

fn prove_page_action_keybindings() -> Vec<ViewKeybinding> {
    vec![
        bind_char('v', "v", "investigate", ViewHotkeyAction::WorkbenchValidate),
        bind_char('t', "t", "trace", ViewHotkeyAction::WorkbenchTraceView),
        bind_char(
            'm',
            "m",
            "boundary",
            ViewHotkeyAction::WorkbenchInvestigationBoundary,
        ),
        bind_char(
            'D',
            "D",
            "defer proof",
            ViewHotkeyAction::WorkbenchDeferProof,
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
    ]
}

/// Single source of truth for the Threat tab digits — consumed by the
/// Navigate-mode keybinding table below AND the early Prompt-mode handler
/// in key_dispatch (digits switch tabs while the composer is empty).
pub(super) fn threat_view_for_digit(key: char) -> Option<ThreatView> {
    Some(match key {
        '1' => ThreatView::Stride,
        '2' => ThreatView::Stories,
        '3' => ThreatView::Scope,
        '4' => ThreatView::Summary,
        '5' => ThreatView::Versions,
        _ => return None,
    })
}

pub(super) fn threat_keybindings() -> Vec<ViewKeybinding> {
    ('1'..='5')
        .filter_map(|key| {
            let view = threat_view_for_digit(key)?;
            Some(bind_char(
                key,
                "1..5",
                "switch threat view",
                ViewHotkeyAction::ThreatView(view),
            ))
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
        // Line/edge scrolling comes from the shared `scroll_keybindings()` base.
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
