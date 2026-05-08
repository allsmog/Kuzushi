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
    let view_lines = shell_view_lines(app, view_area);
    let view_height = (view_lines.len() as u16).clamp(1, max_view_height);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(render_constraints(view_height, &sections))
        .split(area);

    let mut index = 0;
    render_lines(frame, chunks[index], view_lines);
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
pub(crate) enum RenderSection {
    Throttle,
    Status,
    Keybind,
    Budget,
    Plan,
    ThreatPatch,
    Confirm,
    Transcript,
}

impl RenderSection {
    pub(crate) fn render(self, frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
        match self {
            Self::Throttle => render_throttle_banner(frame, area, app),
            Self::Status => render_status_footer(frame, area, app),
            Self::Keybind => render_keybind_footer(frame, area, app),
            Self::Budget => render_cost_cap_halt(frame, area, app),
            Self::Plan => render_plan_card(frame, area, app),
            Self::ThreatPatch => render_threat_patch_card(frame, area, app),
            Self::Confirm => render_confirm_card(frame, area, app),
            Self::Transcript => render_transcript(frame, area, app),
        }
    }
}

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
        section_slot(RenderSection::Transcript, transcript_height(app, area)),
    ]
    .into_iter()
    .flatten()
    .collect()
}
