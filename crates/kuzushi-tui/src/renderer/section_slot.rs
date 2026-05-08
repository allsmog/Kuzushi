use super::*;

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
    match (
        matches!(app.shell_view, ShellView::ModuleRun),
        area.height >= 12,
    ) {
        (false, true) => 2,
        _ => 0,
    }
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
    if app.advisory.throttle.is_some() && area.height >= 5 {
        1
    } else {
        0
    }
}

pub(crate) fn cost_cap_halt_height(app: &ShellApp, area: Rect) -> u16 {
    if app.is_budget_halted() && area.height >= 5 {
        2
    } else {
        0
    }
}
