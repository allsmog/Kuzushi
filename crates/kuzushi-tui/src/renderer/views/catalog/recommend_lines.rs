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
        &[8, 26, 8, 34, value_width(area, 84)],
    ));
    let take = (area.height.saturating_sub(10) as usize).max(4);
    for recommendation in model.rows.iter().take(take) {
        lines.extend(recommendation_lines(recommendation, area.width));
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

/// One recommendation. The reason explains WHY the tool is worth running —
/// truncating it defeats the view — so a reason that overflows its column
/// continues on indented follow-up lines instead of ending in an ellipsis.
fn recommendation_lines(recommendation: &RecommendationRow, width: u16) -> Vec<Line<'static>> {
    const REASON_COLUMN: usize = 8 + 26 + 8 + 34 + 8;
    let [priority, tool, runtime, signal, reason] = &recommendation.cells;
    let reason_width = (width as usize).saturating_sub(REASON_COLUMN).max(24);
    let mut chunks = wrap_text(reason, reason_width);
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    let mut lines = vec![row(&[
        pad(priority, 8),
        pad(tool, 26),
        pad(runtime, 8),
        pad(signal, 34),
        chunks[0].clone(),
    ])];
    for chunk in chunks.iter().skip(1) {
        lines.push(muted(&format!(
            "{:indent$}{chunk}",
            "",
            indent = REASON_COLUMN
        )));
    }
    lines
}
