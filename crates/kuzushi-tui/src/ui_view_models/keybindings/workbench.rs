use super::{bind, FooterKeybinding};
use crate::app::WorkbenchPage;
use crate::ui_view_models::active_workbench_page;
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ShellApp, ShellView};

mod prove_details;
pub(super) use prove_details::prove_detail_bindings;

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    matches!(app.shell_view(), ShellView::Workbench).then(|| workbench_keybindings(app))
}

fn workbench_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    if let Some(mut bindings) = crate::ui_view_models::phase_cockpit::result_keybindings(app) {
        if let Some(reader) = result_reader_binding(app) {
            bindings.insert(0, reader);
        }
        bindings.push(bind("Ctrl+C", workbench_exit_label(app)));
        return bindings;
    }
    let plan = workbench_plan(app);
    if let Some(bindings) = guided_workbench_keybindings(app, plan.as_ref()) {
        return bindings;
    }
    regular_workbench_keybindings(app, plan.as_ref())
}

fn result_reader_binding(app: &ShellApp) -> Option<FooterKeybinding> {
    if scan_coverage_reader_is_open(app) {
        return Some(bind("PgUp/PgDn", "coverage"));
    }
    crate::renderer::workbench_scroll_page_rows(app).map(|_| bind("PgUp/PgDn", "scroll"))
}

fn scan_coverage_reader_is_open(app: &ShellApp) -> bool {
    active_workbench_page(app) == WorkbenchPage::Scan && app.guided_scan_question_model().is_none()
}

fn regular_workbench_keybindings(
    app: &ShellApp,
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) -> Vec<FooterKeybinding> {
    // Keep the phase-native controls copyable at ordinary terminal widths.
    // This is presentation order only; the input dispatcher retains its own
    // first-match ordering.
    let mut bindings = Vec::new();
    push_workbench_view_keybindings(&mut bindings, app, plan);
    combine_findings_page_controls(&mut bindings);
    match focused_enter_binding(app, plan) {
        Some(binding) => replace_enter_binding(&mut bindings, binding),
        None => bindings.retain(|binding| binding.key != "Enter"),
    }
    if map_gallery_is_visible(app) {
        apply_map_gallery_controls(&mut bindings, app);
    }
    prioritize_phase_controls(&mut bindings, plan);
    prioritize_linked_return(&mut bindings, app);
    append_workbench_commands(&mut bindings, app);
    bindings
}

fn prioritize_linked_return(bindings: &mut [FooterKeybinding], app: &ShellApp) {
    if !app.dfd_review_return_is_available()
        && !app.scope_findings_return_is_available()
        && !app.matrix_observation_return_is_available()
    {
        return;
    }
    let Some(key) = app.view_back_key(ShellView::Workbench) else {
        return;
    };
    if let Some(index) = bindings.iter().position(|binding| binding.key == key) {
        bindings[..=index].rotate_right(1);
    }
}

/// The footer names the gallery's controls exactly while the gallery is the
/// canvas being drawn — the same condition that decides whether it owns those
/// keys — so an action-required Map advertises them too instead of leaving
/// them unnamed while they work.
pub(super) fn map_gallery_is_visible(app: &ShellApp) -> bool {
    active_workbench_page(app) == WorkbenchPage::Map
        && crate::ui_view_models::map_gallery_is_canvas(app)
}

fn append_workbench_commands(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    bindings.push(bind("Ctrl+G", "palette"));
    if active_workbench_page(app) != WorkbenchPage::Map {
        bindings.push(bind("scan", "Scan phase planner"));
        bindings.push(bind("scan batch", "plan study and allowance"));
    }
    if !app.findings().is_empty() {
        bindings.push(bind(WORKBENCH_REPORT_COMMAND, "open Report"));
    }
    bindings.push(bind("Ctrl+C", workbench_exit_label(app)));
}

fn apply_map_gallery_controls(bindings: &mut Vec<FooterKeybinding>, app: &ShellApp) {
    const REPLACED: [&str; 9] = [
        "Tab",
        "[",
        "]",
        "Z",
        "z",
        "j/k/↑/↓",
        "g/G",
        "Enter",
        "PgUp/PgDn",
    ];
    bindings.retain(|binding| !REPLACED.contains(&binding.key.as_ref()));
    bindings.extend([
        bind("Tab", "map view"),
        bind("z", "zoom"),
        bind("PgUp/PgDn", map_page_detail_label(app)),
    ]);
    append_map_page_controls(bindings, app.current_map_viz_page());
}

fn append_map_page_controls(bindings: &mut Vec<FooterKeybinding>, page: crate::scene3d::VizPage) {
    match page {
        crate::scene3d::VizPage::Summary => {
            bindings.push(bind("j/k/↑/↓", "component"));
            bindings.push(bind("g/G", "ends"));
            bindings.push(bind("Enter", "DFD target"));
        }
        crate::scene3d::VizPage::Dfd => {
            bindings.push(bind("j/k/↑/↓", "select"));
            bindings.push(bind("f", "findings at paths"));
            bindings.push(bind("s", "plan scan"));
            bindings.push(bind("g", "plan context"));
            bindings.push(bind("Enter", "context"));
        }
        crate::scene3d::VizPage::EntryPoints => {
            bindings.push(bind("j/k/↑/↓", "select"));
            bindings.push(bind("g/G", "ends"));
            bindings.push(bind("Enter", "DFD target"));
        }
        crate::scene3d::VizPage::Components => {
            bindings.push(bind("j/k/↑/↓", "scroll"));
            bindings.push(bind("g/G", "ends"));
        }
        crate::scene3d::VizPage::AttackSurface
        | crate::scene3d::VizPage::AttackPath
        | crate::scene3d::VizPage::Heatmap
        | crate::scene3d::VizPage::ExploitChain
        | crate::scene3d::VizPage::Worklist => {}
    }
}

fn map_page_detail_label(app: &ShellApp) -> &'static str {
    match app.current_map_viz_page() {
        crate::scene3d::VizPage::Summary | crate::scene3d::VizPage::Components => "scroll",
        crate::scene3d::VizPage::Dfd | crate::scene3d::VizPage::EntryPoints => "detail",
        _ => "scroll",
    }
}

fn guided_workbench_keybindings(
    app: &ShellApp,
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) -> Option<Vec<FooterKeybinding>> {
    let guided =
        plan.is_some_and(|plan| plan.density == crate::ui_view_models::LayoutDensity::Guided);
    guided.then(|| vec![bind("Ctrl+C", workbench_exit_label(app))])
}

fn workbench_exit_label(app: &ShellApp) -> &'static str {
    if app.review_decision_write_pending() {
        return "wait for save";
    }
    if app.has_running_work() {
        return "request abort";
    }
    "exit"
}

const PHASE_KEYS: [&str; 8] = ["Shift+Tab", "1..3", "Tab", "[", "]", "Z", "z", "Enter"];
const REVIEW_KEYS: [&str; 26] = [
    "Ctrl+N/P",
    "Ctrl+N",
    "Ctrl+P",
    "Ctrl+F",
    "Enter",
    "j/k/↑/↓",
    "End",
    "G",
    "O",
    "g",
    "PgUp/PgDn",
    "q",
    "r",
    "Shift+Tab",
    "v",
    "x",
    "c",
    "i",
    "n/N",
    "Tab",
    "1..3",
    "[",
    "]",
    "Z",
    "z",
    "g/G",
];

fn combine_findings_page_controls(bindings: &mut Vec<FooterKeybinding>) {
    let next = bindings.iter().position(|binding| binding.key == "Ctrl+N");
    let previous = bindings.iter().position(|binding| binding.key == "Ctrl+P");
    let (Some(next), Some(previous)) = (next, previous) else {
        return;
    };
    bindings[next] = bind("Ctrl+N/P", "pages");
    bindings.remove(previous);
}

fn prioritize_phase_controls(
    bindings: &mut [FooterKeybinding],
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) {
    // Preserve the phase-native controls before secondary cursor shortcuts at
    // compact widths. This changes presentation order only.
    let keys = if focused_surface(plan).is_some_and(|surface| {
        matches!(
            surface.interaction,
            crate::ui_view_models::SurfaceInteraction::Selectable
                | crate::ui_view_models::SurfaceInteraction::Scrollable
        )
    }) {
        REVIEW_KEYS.as_slice()
    } else {
        PHASE_KEYS.as_slice()
    };
    bindings.sort_by_key(|binding| {
        keys.iter()
            .position(|key| *key == binding.key)
            .unwrap_or(keys.len())
    });
}

fn replace_enter_binding(bindings: &mut [FooterKeybinding], replacement: FooterKeybinding) {
    if let Some(binding) = bindings.iter_mut().find(|binding| binding.key == "Enter") {
        *binding = replacement;
    }
}

fn focused_enter_binding(
    app: &ShellApp,
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) -> Option<FooterKeybinding> {
    let page = active_workbench_page(app);
    let surface = focused_surface(plan)?;
    if surface.id == crate::ui_view_models::PhaseSurfaceId::ReviewQueue
        && surface.interaction == crate::ui_view_models::SurfaceInteraction::Static
    {
        return Some(bind("Enter", "scan guidance"));
    }
    (surface.interaction == crate::ui_view_models::SurfaceInteraction::Selectable).then(|| {
        if page == WorkbenchPage::Review {
            bind("Enter", "detail")
        } else {
            bind("Enter", "open")
        }
    })
}

fn focused_surface(
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) -> Option<crate::ui_view_models::PlannedPhaseSurface> {
    let plan = plan?;
    plan.surface(plan.effective_focus).copied()
}

fn push_workbench_view_keybindings(
    bindings: &mut Vec<FooterKeybinding>,
    app: &ShellApp,
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) {
    for binding in app.workbench_view_keybindings_for_plan(plan) {
        let candidate = bind(binding.hint, binding.label);
        if !bindings.contains(&candidate) {
            bindings.push(candidate);
        }
    }
}

fn workbench_plan(app: &ShellApp) -> Option<crate::ui_view_models::PhasePresentationPlan> {
    let viewport = app.viewport();
    crate::renderer::workbench_phase_plan_for_app(
        app,
        ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
    )
}
