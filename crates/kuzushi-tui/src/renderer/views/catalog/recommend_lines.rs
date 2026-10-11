use super::*;
use crate::ui_view_models::{
    recommendation_model, ComponentRecommendationRow, RecommendationModel, RecommendationRow,
};

pub(crate) fn recommend_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = recommendation_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(model.title, area.width));

    append_receipt_rows(&mut lines, &model, area.width as usize);
    if let Some(surface) = &model.attack_surface {
        lines.push(attack_surface_risk_line(surface, area.width));
    }
    lines.push(blank());

    if model.rows.is_empty() && model.components.is_empty() {
        append_empty_recommendations(lines, &model, area)
    } else {
        append_report(lines, &model, area, app.router.catalog().recommend_cursor())
    }
}

fn append_report(
    mut lines: Vec<Line<'static>>,
    model: &RecommendationModel,
    area: Rect,
    recommend_cursor: usize,
) -> Vec<Line<'static>> {
    lines.push(muted("r refresh deterministic · Navigate mode"));
    if let Some(summary) = &model.summary {
        lines.push(muted(&fit(&summary, area.width as usize)));
        lines.push(blank());
    }
    append_components(&mut lines, model, area, recommend_cursor);
    append_recommendation_rows(&mut lines, model, area.width as usize);
    lines.push(blank());
    lines.push(command_list_line(
        &model.report_commands,
        area.width as usize,
    ));
    lines
}

fn append_receipt_rows(lines: &mut Vec<Line<'static>>, model: &RecommendationModel, width: usize) {
    let mut rows = model.detail_rows.iter().collect::<Vec<_>>();
    rows.sort_by_key(|row| receipt_order(&row.cells[0]));
    for row in rows {
        let field = format!("{}: {}", row.cells[0], row.cells[1]);
        lines.extend(
            wrap_text(&field, width.max(1))
                .into_iter()
                .map(|line| muted(&line)),
        );
    }
}

fn receipt_order(label: &str) -> usize {
    [
        "ranking",
        "inventory",
        "coverage",
        "history",
        "recommendations",
        "run",
    ]
    .iter()
    .position(|candidate| *candidate == label)
    .unwrap_or(6)
}

fn append_recommendation_rows(
    lines: &mut Vec<Line<'static>>,
    model: &RecommendationModel,
    width: usize,
) {
    if model.rows.is_empty() {
        return;
    }
    if width < 96 {
        append_recommendation_cards(lines, model, width);
        return;
    }
    let widths = recommendation_widths(width);
    lines.push(aligned_header(&model.report_headers, &widths));
    for recommendation in &model.rows {
        lines.extend(recommendation_lines(recommendation, &widths));
    }
}

fn append_recommendation_cards(
    lines: &mut Vec<Line<'static>>,
    model: &RecommendationModel,
    width: usize,
) {
    for recommendation in &model.rows {
        lines.extend(recommendation_card(recommendation, width));
    }
}

fn recommendation_card(recommendation: &RecommendationRow, width: usize) -> Vec<Line<'static>> {
    let [priority, tool, runtime, signal, reason] = &recommendation.cells;
    let fields = [
        format!("{priority} · {tool}"),
        format!("Runtime required: {runtime}"),
        format!("Signal: {signal}"),
        format!("Reason: {reason}"),
    ];
    let mut lines = Vec::new();
    for field in fields {
        lines.extend(
            wrap_text(&field, width.max(1))
                .into_iter()
                .map(|line| row(&[line])),
        );
    }
    lines.push(blank());
    lines
}

fn recommendation_widths(width: usize) -> [usize; 5] {
    fit_table_widths(width, [8, 26, 8, 34, 40], [3, 8, 3, 6, 4])
}

fn append_components(
    lines: &mut Vec<Line<'static>>,
    model: &RecommendationModel,
    area: Rect,
    recommend_cursor: usize,
) {
    if model.components.is_empty() {
        return;
    }
    lines.push(divider("COMPONENTS", area.width));
    let selected = recommend_cursor.min(model.components.len().saturating_sub(1));
    for (index, component) in model.components.iter().enumerate() {
        lines.extend(component_lines(component, area.width, index == selected));
    }
    lines.push(blank());
}

fn component_lines(
    component: &ComponentRecommendationRow,
    width: u16,
    selected: bool,
) -> Vec<Line<'static>> {
    let marker = if selected { "▌" } else { " " };
    let title = format!(
        "{marker} ◆ {} · {} · risk {} · {}",
        component.class_label, component.tier_label, component.risk_score, component.rel_path
    );
    let widths = fit_table_widths(width as usize, [38, 40], [12, 8]);
    let mut lines = vec![row(&[
        pad(&title, widths[0]),
        pad(&component.reason, widths[1]),
    ])];
    lines.push(muted(&fit(
        &format!("scan focused: {}", component.scan_command),
        width as usize,
    )));
    if let Some(command) = &component.promote_command {
        lines.push(muted(&fit(
            &format!("promote target: {command}"),
            width as usize,
        )));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_width(line: &Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum()
    }

    #[test]
    fn recommendation_columns_fit_narrow_area_budgets() {
        let row = RecommendationRow {
            cells: [
                "high".to_string(),
                "tool:日本語-long".to_string(),
                "agent".to_string(),
                "a detailed signal".to_string(),
                "a long reason that wraps without crossing the terminal edge".to_string(),
            ],
        };
        for width in [40, 60, 80] {
            let widths = recommendation_widths(width);
            let lines = recommendation_lines(&row, &widths);

            assert_eq!(table_width(&widths), width);
            assert!(lines.iter().all(|line| line_width(line) <= width));
        }
    }

    #[test]
    fn narrow_recommendation_cards_preserve_identity_signal_and_rationale() {
        let row = RecommendationRow {
            cells: [
                "high".into(),
                "a-long-module-name:metadata-action".into(),
                "no".into(),
                "A signal that must remain readable at narrow widths.".into(),
                "Complete rationale including the final supporting fact.".into(),
            ],
        };
        for width in [40, 60, 80] {
            let lines = recommendation_card(&row, width);
            assert!(lines.iter().all(|line| line_width(line) <= width));
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(text.contains(&row.cells[1]));
            assert!(text.contains(&row.cells[3]));
            assert!(text.contains(&row.cells[4]));
        }
    }

    #[test]
    fn recommendation_receipts_wrap_full_coverage_and_source_identity() {
        let mut model =
            recommendation_model(&ShellApp::new(kuzushi_core::V2Config::default(), None));
        let mut inventory = model.detail_rows[0].clone();
        inventory.cells = [
            "inventory".into(),
            "partial; 12 entries; 1 clipped files; 123 omitted paths".into(),
        ];
        let mut identity = inventory.clone();
        identity.cells = [
            "run".into(),
            "recommendation-history-source-identity".into(),
        ];
        model.detail_rows = vec![inventory, identity];
        for width in [40, 60, 80] {
            let mut lines = Vec::new();
            append_receipt_rows(&mut lines, &model, width);
            assert!(lines.iter().all(|line| line_width(line) <= width));
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains("123 omitted paths"));
            assert!(text.contains("recommendation-history-source-identity"));
        }
    }
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
fn recommendation_lines(
    recommendation: &RecommendationRow,
    widths: &[usize; 5],
) -> Vec<Line<'static>> {
    let [priority, tool, runtime, signal, reason] = &recommendation.cells;
    let reason_width = widths[4].max(1);
    let mut chunks = wrap_text(reason, reason_width);
    if chunks.is_empty() {
        chunks.push(String::new());
    }
    let mut lines = vec![row(&[
        pad(priority, widths[0]),
        pad(tool, widths[1]),
        pad(runtime, widths[2]),
        pad(signal, widths[3]),
        pad(&chunks[0], widths[4]),
    ])];
    let reason_column = widths[..4].iter().sum::<usize>() + table_gap_width(5);
    for chunk in chunks.iter().skip(1) {
        lines.push(muted(&format!(
            "{:reason_column$}{}",
            "",
            fit(chunk, widths[4])
        )));
    }
    lines
}
