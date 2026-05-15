use super::*;
use crate::ui_view_models::{cost_cap_halt_model, throttle_banner_model, transcript_chrome_height};

pub(crate) fn section_slot(kind: RenderSection, height: u16) -> Option<RenderSectionSlot> {
    (height > 0).then_some(RenderSectionSlot { kind, height })
}

pub(crate) fn fixed_chrome_height(sections: &[RenderSectionSlot]) -> u16 {
    PROMPT_HEIGHT + sections.iter().map(|section| section.height).sum::<u16>()
}

pub(crate) fn render_constraints(
    view_height: u16,
    sections: &[RenderSectionSlot],
) -> Vec<Constraint> {
    let mut constraints = vec![Constraint::Length(view_height), Constraint::Min(0)];
    constraints.extend(
        sections
            .iter()
            .map(|section| Constraint::Length(section.height)),
    );
    constraints.push(Constraint::Length(PROMPT_HEIGHT));
    constraints
}

pub(crate) fn transcript_height(app: &ShellApp, area: Rect) -> u16 {
    transcript_chrome_height(app, area.height)
}

pub(crate) fn keybind_footer_height(area: Rect) -> u16 {
    if area.height >= 8 {
        2
    } else {
        0
    }
}

pub(crate) fn status_footer_height(area: Rect) -> u16 {
    if area.height >= 6 {
        1
    } else {
        0
    }
}

pub(crate) fn throttle_banner_height(app: &ShellApp, area: Rect) -> u16 {
    if throttle_banner_model(app).is_some() && area.height >= 5 {
        1
    } else {
        0
    }
}

pub(crate) fn cost_cap_halt_height(app: &ShellApp, area: Rect) -> u16 {
    if cost_cap_halt_model(app).is_some() && area.height >= 5 {
        2
    } else {
        0
    }
}
