use super::*;
/// How the primary body region is painted this frame. Most views are
/// line-based; Activity, the Workbench command center, and the 3D
/// attack-surface page each own the whole region with a frame-level layout
/// (split panes / half-block framebuffer).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PrimaryRenderMode {
    Lines,
    Activity,
    Scene,
    Workbench,
}

struct PrimaryLayer {
    view: ShellView,
    mode: PrimaryRenderMode,
    height: u16,
    lines: Vec<Line<'static>>,
    has_overlay: bool,
}

fn primary_render_mode(app: &ShellApp, view: ShellView) -> PrimaryRenderMode {
    if view == app.shell_view() {
        return current_primary_render_mode(app);
    }
    match view {
        ShellView::Scene if app.router.scene().page().is_frame_rendered() => {
            PrimaryRenderMode::Scene
        }
        ShellView::Activity => PrimaryRenderMode::Activity,
        ShellView::Workbench => PrimaryRenderMode::Workbench,
        _ => PrimaryRenderMode::Lines,
    }
}

fn current_primary_render_mode(app: &ShellApp) -> PrimaryRenderMode {
    if crate::ui_view_models::uses_scene_frame(app) {
        return PrimaryRenderMode::Scene;
    }
    if crate::ui_view_models::uses_activity_frame(app) {
        return PrimaryRenderMode::Activity;
    }
    if crate::ui_view_models::uses_workbench_frame(app) {
        return PrimaryRenderMode::Workbench;
    }
    PrimaryRenderMode::Lines
}

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let sections = fit_sections_to_height(render_sections(app, area), area.height);
    let fixed_height = fixed_chrome_height(&sections);
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let primary = primary_layer(app, area, max_view_height);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(render_constraints(primary.height, &sections))
        .split(area);
    render_primary_layer(frame, chunks[0], app, primary);
    render_lower_chrome(frame, app, &chunks, sections);
}

fn render_primary_layer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, primary: PrimaryLayer) {
    render_primary_view(frame, area, app, primary.view, primary.mode, primary.lines);
    if primary.has_overlay {
        render_contextual_overlay(frame, area, app);
    }
}

fn primary_layer(app: &ShellApp, area: Rect, max_height: u16) -> PrimaryLayer {
    let overlay = contextual_overlay_origin(app);
    let view = overlay.unwrap_or_else(|| app.shell_view());
    let mode = primary_render_mode(app, view);
    let force_full_height = mode != PrimaryRenderMode::Lines || overlay.is_some();
    let view_area = Rect {
        height: max_height,
        ..area
    };
    let (height, lines) =
        main_view_layout(app, view, mode, force_full_height, max_height, view_area);
    PrimaryLayer {
        view,
        mode,
        height,
        lines,
        has_overlay: overlay.is_some(),
    }
}

fn render_lower_chrome(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    chunks: &[Rect],
    sections: Vec<RenderSectionSlot>,
) {
    let mut index = 2;
    for section in sections {
        section.kind.render(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
}

fn main_view_layout(
    app: &ShellApp,
    view: ShellView,
    mode: PrimaryRenderMode,
    force_full_height: bool,
    max_view_height: u16,
    view_area: Rect,
) -> (u16, Vec<Line<'static>>) {
    if mode != PrimaryRenderMode::Lines {
        return (max_view_height, Vec::new());
    }

    let view_lines = shell_view_lines_for(app, view_area, view);
    let view_height = if force_full_height {
        max_view_height
    } else {
        line_view_height(view, view_lines.len(), max_view_height)
    };
    (view_height, view_lines)
}

fn line_view_height(view: ShellView, line_count: usize, max_view_height: u16) -> u16 {
    if matches!(view, crate::ShellView::PlanningPicker) {
        return max_view_height;
    }
    (line_count as u16).clamp(1, max_view_height)
}

fn render_primary_view(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    view: ShellView,
    mode: PrimaryRenderMode,
    view_lines: Vec<Line<'static>>,
) {
    match mode {
        PrimaryRenderMode::Scene => render_scene_view(frame, area, app),
        PrimaryRenderMode::Activity => render_activity_view(frame, area, app),
        PrimaryRenderMode::Workbench => render_workbench_view(frame, area, app),
        PrimaryRenderMode::Lines => render_line_view(frame, area, view, view_lines),
    }
}

fn render_line_view(
    frame: &mut Frame<'_>,
    area: Rect,
    view: ShellView,
    view_lines: Vec<Line<'static>>,
) {
    if matches!(view, crate::ShellView::PlanningPicker) {
        render_centered_lines(frame, area, view_lines);
    } else {
        render_lines(frame, area, view_lines);
    }
}

fn contextual_overlay_origin(app: &ShellApp) -> Option<ShellView> {
    app.router
        .overlay_origin()
        .filter(|view| *view != app.shell_view())
}

fn render_contextual_overlay(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if app.shell_view() == ShellView::CommandPalette {
        render_command_palette_overlay(frame, area, app);
        return;
    }
    render_system_overlay(frame, area, app);
}

fn render_centered_lines(frame: &mut Frame<'_>, area: Rect, lines: Vec<Line<'static>>) {
    if area.height == 0 || lines.is_empty() {
        return;
    }
    let content_height = (lines.len() as u16).min(area.height);
    let top_padding = area.height.saturating_sub(content_height) / 2;
    render_lines(
        frame,
        Rect {
            y: area.y.saturating_add(top_padding),
            height: content_height,
            ..area
        },
        lines,
    );
}

pub(crate) const PROMPT_HEIGHT: u16 = 1;

#[derive(Clone, Copy)]
pub(crate) struct RenderSectionSlot {
    pub(crate) kind: RenderSection,
    pub(crate) height: u16,
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum RenderSection {
    Notice,
    Throttle,
    Status,
    Keybind,
    Budget,
    Plan,
    ThreatPatch,
    Confirm,
    Retry,
    PrereqPrompt,
    Transcript,
    /// Completion popup (M3 §3.3). Sits just above the prompt when a
    /// completion cycle is active, showing up to 6 candidates with the
    /// selected one highlighted.
    CompletionPopup,
}

impl RenderSection {
    pub(crate) fn render(self, frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
        RENDER_SECTION_HANDLERS[self as usize](frame, area, app);
    }
}

type RenderSectionHandler = fn(&mut Frame<'_>, Rect, &ShellApp);

const RENDER_SECTION_HANDLERS: &[RenderSectionHandler] = &[
    render_notice_banner,
    render_throttle_banner,
    render_status_footer,
    render_keybind_footer,
    render_cost_cap_halt,
    render_plan_card,
    render_threat_patch_card,
    render_confirm_card,
    render_retry_card,
    render_prereq_prompt_card,
    render_transcript,
    render_completion_popup,
];

pub(crate) fn render_sections(app: &ShellApp, area: Rect) -> Vec<RenderSectionSlot> {
    [
        section_slot(RenderSection::Budget, cost_cap_halt_height(app, area)),
        section_slot(RenderSection::Notice, notice_banner_height(app, area)),
        section_slot(RenderSection::Throttle, throttle_banner_height(app, area)),
        section_slot(RenderSection::Status, status_footer_height(app, area)),
        section_slot(RenderSection::Keybind, keybind_footer_height(app, area)),
        section_slot(RenderSection::Plan, plan_card_height(app, area)),
        section_slot(
            RenderSection::ThreatPatch,
            threat_patch_card_height(app, area),
        ),
        section_slot(RenderSection::Confirm, confirm_card_height(app, area)),
        section_slot(RenderSection::Retry, retry_card_height(app, area)),
        section_slot(
            RenderSection::PrereqPrompt,
            prereq_prompt_card_height(app, area),
        ),
        section_slot(RenderSection::Transcript, transcript_height(app, area)),
        section_slot(
            RenderSection::CompletionPopup,
            completion_popup_height(app, area),
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}
