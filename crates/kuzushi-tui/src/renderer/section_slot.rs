use super::*;
use crate::ui_view_models::{
    cost_cap_halt_model, keybind_footer_chrome_height, notice_banner_model,
    status_footer_chrome_height, throttle_banner_model, transcript_chrome_height,
};

pub(crate) fn section_slot(kind: RenderSection, height: u16) -> Option<RenderSectionSlot> {
    (height > 0).then_some(RenderSectionSlot { kind, height })
}

pub(crate) fn fixed_chrome_height(sections: &[RenderSectionSlot], prompt_height: u16) -> u16 {
    prompt_height + sections.iter().map(|section| section.height).sum::<u16>()
}

/// Smallest primary-view height we refuse to drop below. Without this, a pile-up
/// of simultaneously-active chrome cards (notice + plan + confirm + transcript…)
/// on a short terminal collapses the main view to a single row and Ratatui then
/// clips the prompt and lower cards. `render_sections` orders slots
/// most-critical-first, so shedding from the tail drops the least important
/// (completion popup, transcript) before the footers and approval gates.
const MIN_PRIMARY_VIEW_HEIGHT: u16 = 3;

pub(crate) fn fit_sections_to_height(
    mut sections: Vec<RenderSectionSlot>,
    area_height: u16,
    prompt_height: u16,
) -> Vec<RenderSectionSlot> {
    let min_primary_height = min_primary_view_height(&sections);
    while !sections.is_empty()
        && fixed_chrome_height(&sections, prompt_height).saturating_add(min_primary_height)
            > area_height
    {
        sections.pop();
    }
    sections
}

fn min_primary_view_height(sections: &[RenderSectionSlot]) -> u16 {
    if sections
        .iter()
        .any(|section| matches!(section.kind, RenderSection::Budget))
    {
        1
    } else {
        MIN_PRIMARY_VIEW_HEIGHT
    }
}

pub(crate) fn render_constraints(
    view_height: u16,
    sections: &[RenderSectionSlot],
    prompt_height: u16,
) -> Vec<Constraint> {
    let mut constraints = vec![Constraint::Length(view_height), Constraint::Min(0)];
    constraints.extend(
        sections
            .iter()
            .map(|section| Constraint::Length(section.height)),
    );
    constraints.push(Constraint::Length(prompt_height));
    constraints
}

pub(crate) fn transcript_height(app: &ShellApp, area: Rect) -> u16 {
    transcript_chrome_height(app, area.height)
}

pub(crate) fn keybind_footer_height(app: &ShellApp, area: Rect) -> u16 {
    if compact_guided_question_owns_footer(app, area) {
        return 0;
    }
    keybind_footer_chrome_height(app, area.height, area.width)
}

pub(crate) fn status_footer_height(app: &ShellApp, area: Rect) -> u16 {
    if compact_guided_question_owns_footer(app, area) {
        return 0;
    }
    status_footer_chrome_height(app, area.height)
}

pub(crate) fn throttle_banner_height(app: &ShellApp, area: Rect) -> u16 {
    if throttle_banner_model(app).is_some() && area.height >= 5 {
        1
    } else {
        0
    }
}

pub(crate) fn notice_banner_height(app: &ShellApp, area: Rect) -> u16 {
    if compact_guided_question_owns_footer(app, area)
        || notice_banner_model(app).is_none()
        || area.height < 5
    {
        return 0;
    }
    // Tall terminals get the full wrapped banner; cramped ones one line, so
    // the reserved rows always match what render_notice_banner draws.
    let max_lines = if area.height >= 10 {
        NOTICE_BANNER_MAX_LINES
    } else {
        1
    };
    notice_banner_line_count(app, area.width, max_lines) as u16
}

fn compact_guided_question_owns_footer(app: &ShellApp, area: Rect) -> bool {
    area.height <= 16 && app.guided_scan_question_is_open()
}

pub(crate) fn cost_cap_halt_height(app: &ShellApp, area: Rect) -> u16 {
    if cost_cap_halt_model(app).is_none() || area.height == 0 {
        return 0;
    }
    if area.height >= 5 {
        2
    } else {
        1
    }
}
