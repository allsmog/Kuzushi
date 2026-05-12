use super::*;

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
    // Activity view uses a true Ratatui split-pane (frame-level), not the
    // shared line-based path. Skip the line computation entirely.
    let activity_mode = matches!(app.shell_view, ShellView::Activity);
    let view_lines = if activity_mode {
        Vec::new()
    } else {
        shell_view_lines(app, view_area)
    };
    let view_height = if activity_mode {
        max_view_height
    } else {
        (view_lines.len() as u16).clamp(1, max_view_height)
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(render_constraints(view_height, &sections))
        .split(area);

    let mut index = 0;
    if activity_mode {
        render_activity_view(frame, chunks[index], app);
    } else {
        render_lines(frame, chunks[index], view_lines);
    }
    index += 1;
    index += 1;
    for section in sections {
        section.kind.render(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
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
    Throttle,
    Status,
    Keybind,
    Budget,
    Plan,
    ThreatPatch,
    Confirm,
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
    render_throttle_banner,
    render_status_footer,
    render_keybind_footer,
    render_cost_cap_halt,
    render_plan_card,
    render_threat_patch_card,
    render_confirm_card,
    render_prereq_prompt_card,
    render_transcript,
];

pub(crate) fn render_sections(app: &ShellApp, area: Rect) -> Vec<RenderSectionSlot> {
    [
        section_slot(RenderSection::Throttle, throttle_banner_height(app, area)),
        section_slot(RenderSection::Status, status_footer_height(area)),
        section_slot(RenderSection::Keybind, keybind_footer_height(area)),
        section_slot(RenderSection::Budget, cost_cap_halt_height(app, area)),
        section_slot(RenderSection::Plan, plan_card_height(app, area)),
        section_slot(
            RenderSection::ThreatPatch,
            threat_patch_card_height(app, area),
        ),
        section_slot(RenderSection::Confirm, confirm_card_height(app, area)),
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
