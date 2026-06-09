use super::*;
use crate::ui_view_models::{uses_activity_frame, uses_scene_frame};

/// How the primary body region is painted this frame. Most views are
/// line-based; Activity and the 3D attack-surface page each own the whole
/// region with a frame-level layout (split panes / half-block framebuffer).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PrimaryRenderMode {
    Lines,
    Activity,
    Scene,
}

fn primary_render_mode(app: &ShellApp) -> PrimaryRenderMode {
    if uses_scene_frame(app) {
        PrimaryRenderMode::Scene
    } else if uses_activity_frame(app) {
        PrimaryRenderMode::Activity
    } else {
        PrimaryRenderMode::Lines
    }
}

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let sections = render_sections(app, area);
    let fixed_height = fixed_chrome_height(&sections);
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let view_area = Rect {
        height: max_view_height,
        ..area
    };
    // Activity and the 3D playground use a true frame-level layout, not the
    // shared line-based path. Skip the line computation entirely for them.
    let mode = primary_render_mode(app);
    let frame_mode = mode != PrimaryRenderMode::Lines;
    let (view_height, view_lines) =
        main_view_layout(app, frame_mode, max_view_height, view_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(render_constraints(view_height, &sections))
        .split(area);

    let mut index = 0;
    render_primary_view(frame, chunks[index], app, mode, view_lines);
    index += 1;
    index += 1;
    for section in sections {
        section.kind.render(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
}

fn main_view_layout(
    app: &ShellApp,
    frame_mode: bool,
    max_view_height: u16,
    view_area: Rect,
) -> (u16, Vec<Line<'static>>) {
    if frame_mode {
        return (max_view_height, Vec::new());
    }

    let view_lines = shell_view_lines(app, view_area);
    let view_height = (view_lines.len() as u16).clamp(1, max_view_height);
    (view_height, view_lines)
}

fn render_primary_view(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &ShellApp,
    mode: PrimaryRenderMode,
    view_lines: Vec<Line<'static>>,
) {
    match mode {
        PrimaryRenderMode::Scene => render_scene_view(frame, area, app),
        PrimaryRenderMode::Activity => render_activity_view(frame, area, app),
        PrimaryRenderMode::Lines => render_lines(frame, area, view_lines),
    }
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
];

pub(crate) fn render_sections(app: &ShellApp, area: Rect) -> Vec<RenderSectionSlot> {
    [
        section_slot(RenderSection::Notice, notice_banner_height(app, area)),
        section_slot(RenderSection::Throttle, throttle_banner_height(app, area)),
        section_slot(RenderSection::Status, status_footer_height(app, area)),
        section_slot(RenderSection::Keybind, keybind_footer_height(app, area)),
        section_slot(RenderSection::Budget, cost_cap_halt_height(app, area)),
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
    ]
    .into_iter()
    .flatten()
    .collect()
}
