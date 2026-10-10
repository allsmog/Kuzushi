//! Complete readiness text shares the overview's actual plan projection.
use super::*;

pub(crate) struct SetupDetailScroll {
    pub(crate) max_offset: usize,
    pub(crate) page_rows: usize,
}

pub(crate) fn setup_detail_scroll(app: &ShellApp) -> Option<SetupDetailScroll> {
    if app.shell_view() != crate::ShellView::Setup
        || app.router.setup().editor() != Some(crate::app::SetupEditor::Details)
    {
        return None;
    }
    let size = app.viewport();
    let area =
        crate::renderer::workbench_primary_area(app, Rect::new(0, 0, size.columns, size.rows));
    let total = detail_document(app, &setup_readiness_model(app), area.width as usize).len();
    let page_rows = usize::from(area.height).saturating_sub(3).max(1);
    Some(SetupDetailScroll {
        max_offset: total.saturating_sub(2 + page_rows),
        page_rows,
    })
}

pub(super) fn detail_lines(
    app: &ShellApp,
    model: &crate::ui_view_models::SetupReadinessModel,
    area: Rect,
) -> Vec<Line<'static>> {
    pinned_document_viewport_lines(
        detail_document(app, model, area.width as usize),
        area.height,
        app.router.setup().detail_scroll(),
        2,
    )
}

fn detail_document(
    app: &ShellApp,
    model: &crate::ui_view_models::SetupReadinessModel,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(row) = model.rows.get(app.router.setup().cursor()) else {
        return Vec::new();
    };
    let mut lines = vec![
        divider(
            &format!("SETUP DETAILS · {}", row.label),
            width.min(u16::MAX as usize) as u16,
        ),
        muted(&format!("State: {} · inspection only", row.status)),
        blank(),
    ];
    lines.extend(wrap_text(&row.detail, width).into_iter().map(Line::raw));
    lines.extend(target_fact_details(app, row, width));
    lines.extend([blank(), styled("PLANNED WORK", theme::accent())]);
    lines.extend(setup_summary_lines(model, width));
    lines.push(blank());
    lines.extend(wrap_text("Reading changes no option, context, allowance or phase. Tab/Esc returns to the same Setup row. Enter does not start work here.",width).into_iter().map(|line|muted(&line)));
    lines
}

fn target_fact_details(
    app: &ShellApp,
    row: &SetupReadinessRow,
    width: usize,
) -> Vec<Line<'static>> {
    if row.id != crate::app::SetupRowId::Target {
        return Vec::new();
    }
    app.active_target_facts()
        .into_iter()
        .flat_map(|facts| crate::ui_view_models::target_fact_detail_lines(facts))
        .flat_map(|line| wrap_text(&line, width))
        .map(Line::raw)
        .collect()
}
