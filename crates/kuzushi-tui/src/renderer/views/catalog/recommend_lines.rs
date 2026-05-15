use super::*;
use crate::ui_view_models::{recommendation_model, RecommendationModel, RecommendationRow};

pub(crate) fn recommend_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = recommendation_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(model.title, area.width));

    for row in &model.detail_rows {
        lines.push(detail(&row.cells[0], &row.cells[1]));
    }
    if let Some(surface) = &model.attack_surface {
        lines.push(attack_surface_risk_line(surface, area.width));
    }
    lines.push(blank());

    if model.rows.is_empty() {
        append_empty_recommendations(lines, &model, area)
    } else {
        append_report(lines, &model, area)
    }
}

fn append_report(
    mut lines: Vec<Line<'static>>,
    model: &RecommendationModel,
    area: Rect,
) -> Vec<Line<'static>> {
    if let Some(summary) = &model.summary {
        lines.push(muted(&fit(&summary, area.width as usize)));
        lines.push(blank());
    }
    lines.push(aligned_header(
        &model.report_headers,
        &[6, 26, 8, value_width(area, 48)],
    ));
    let take = (area.height.saturating_sub(10) as usize).max(4);
    for recommendation in model.rows.iter().take(take) {
        lines.push(recommendation_row(recommendation, area.width));
    }
    lines.push(blank());
    lines.push(command_list_line(
        &model.report_commands,
        area.width as usize,
    ));
    lines
}

fn append_empty_recommendations(
    mut lines: Vec<Line<'static>>,
    model: &RecommendationModel,
    area: Rect,
) -> Vec<Line<'static>> {
    let empty = &model.empty_state;
    lines.extend(empty_state_panel(
        empty.title,
        &empty.explanations,
        &empty.actions,
    ));
    lines.push(command_list_line(&empty.commands, area.width as usize));
    lines
}

fn recommendation_row(recommendation: &RecommendationRow, width: u16) -> Line<'static> {
    let [priority, tool, runtime, reason] = &recommendation.cells;
    let reason_width = (width as usize).saturating_sub(44).max(24);
    row(&[
        pad(priority, 6),
        pad(tool, 26),
        pad(runtime, 8),
        fit(reason, reason_width),
    ])
}
