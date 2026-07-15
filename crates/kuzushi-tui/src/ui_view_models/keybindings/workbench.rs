use super::{bind, FooterKeybinding};
use crate::app::WorkbenchPage;
use crate::ui_view_models::active_workbench_page;
use crate::ui_view_models::WORKBENCH_REPORT_COMMAND;
use crate::{ShellApp, ShellView};

pub(super) fn keybindings(app: &ShellApp) -> Option<Vec<FooterKeybinding>> {
    matches!(app.shell_view(), ShellView::Workbench).then(|| workbench_keybindings(app))
}

fn workbench_keybindings(app: &ShellApp) -> Vec<FooterKeybinding> {
    let plan = workbench_plan(app);
    if plan
        .as_ref()
        .is_some_and(|plan| plan.density == crate::ui_view_models::LayoutDensity::Guided)
    {
        return vec![bind("Ctrl+C", "request abort")];
    }
    // Keep the phase-native controls copyable at ordinary terminal widths.
    // This is presentation order only; the input dispatcher retains its own
    // first-match ordering.
    let mut bindings = Vec::new();
    push_workbench_view_keybindings(&mut bindings, app, plan.as_ref());
    match focused_enter_binding(app, plan.as_ref()) {
        Some(binding) => replace_enter_binding(&mut bindings, binding),
        None => bindings.retain(|binding| binding.key != "Enter"),
    }
    prioritize_phase_controls(&mut bindings, plan.as_ref());
    bindings.extend([
        bind("Ctrl+G", "palette"),
        bind("scan", "guided plan"),
        bind("run sast:scan {}", "rescan now"),
    ]);
    if !app.findings().is_empty() {
        bindings.push(bind(WORKBENCH_REPORT_COMMAND, "open Report"));
    }
    bindings.push(bind("Ctrl+C", "exit"));
    bindings
}

fn prioritize_phase_controls(
    bindings: &mut [FooterKeybinding],
    plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
) {
    // Preserve the phase-native controls before secondary cursor shortcuts at
    // compact widths. This changes presentation order only.
    const PHASE_KEYS: [&str; 8] = ["Shift+Tab", "1..5", "Tab", "[", "]", "Z", "z", "Enter"];
    const REVIEW_KEYS: [&str; 15] = [
        "Shift+Tab",
        "q",
        "Enter",
        "j/k/↑/↓",
        "v",
        "x",
        "c",
        "n/N",
        "Tab",
        "1..5",
        "[",
        "]",
        "Z",
        "z",
        "g/G",
    ];
    let keys = if focused_surface(plan).is_some_and(|surface| {
        surface.interaction == crate::ui_view_models::SurfaceInteraction::Selectable
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
            bind("Enter", "review")
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
