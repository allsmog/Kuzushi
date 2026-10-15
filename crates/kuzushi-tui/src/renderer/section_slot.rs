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
    let Some(notice) = notice_banner_model(app) else {
        return 0;
    };
    if compact_guided_question_owns_footer(app, area) || area.height < 5 {
        return 0;
    }
    let max_lines = notice_line_limit(
        area.height,
        notice.dismiss_on_escape,
        crate::ui_view_models::compact_document_notice(app, area.height),
    );
    notice_banner_line_count(app, area.width, max_lines) as u16
}

/// Compact documents keep their outcome readable alongside the error badge.
fn notice_line_limit(height: u16, captures_escape: bool, compact_document: bool) -> usize {
    match (height, captures_escape, compact_document) {
        (0..=9, _, _) | (10..=12, false, _) | (10..=12, _, true) => 1,
        _ => NOTICE_BANNER_MAX_LINES,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_gallery_errors_leave_room_for_the_failure_document() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Scene);
        app.set_viewport(crate::TerminalViewport::new(40, 12));
        app.set_error_notice(
            "tool",
            "Owned dependency inventory failure with a long path and a complete recorded cause",
        );
        let full = Rect::new(0, 0, 40, 12);
        assert_eq!(notice_banner_height(&app, full), 1);
        assert!(crate::renderer::primary_body_area(&app, full).height >= 6);
        app.set_shell_view(crate::ShellView::Logs);
        assert_eq!(notice_banner_height(&app, full), 3);
    }

    fn slot(kind: RenderSection, height: u16) -> RenderSectionSlot {
        RenderSectionSlot { kind, height }
    }

    #[test]
    fn compact_allocation_sheds_passive_throttle_before_decision_gates() {
        let sections = vec![
            slot(RenderSection::Confirm, 4),
            slot(RenderSection::PrereqPrompt, 4),
            slot(RenderSection::Throttle, 1),
        ];

        let fitted = fit_sections_to_height(sections, 12, 1);
        let kinds = fitted
            .iter()
            .map(|slot| slot.kind as usize)
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            vec![
                RenderSection::Confirm as usize,
                RenderSection::PrereqPrompt as usize
            ]
        );
    }

    #[test]
    fn each_interactive_gate_survives_a_40_by_12_allocation() {
        for gate in [
            RenderSection::ThreatPatch,
            RenderSection::Confirm,
            RenderSection::PrereqPrompt,
        ] {
            let fitted = fit_sections_to_height(
                vec![
                    slot(
                        gate,
                        if matches!(gate, RenderSection::ThreatPatch) {
                            5
                        } else {
                            4
                        },
                    ),
                    slot(RenderSection::Status, 1),
                    slot(RenderSection::Throttle, 1),
                    slot(RenderSection::Transcript, 3),
                ],
                12,
                1,
            );
            assert!(
                fitted
                    .iter()
                    .any(|slot| slot.kind as usize == gate as usize),
                "interactive gate was hidden while its keys remain active"
            );
        }
    }
}
