use super::*;
use crate::ui_view_models::{strategy_queue_model, StrategyQueueModel, StrategyQueueRow};

pub(crate) fn strategy_queue_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = strategy_queue_model(app);

    lines.push(blank());
    lines.push(divider(model.title, area.width));
    append_strategy_queue_details(&mut lines, &model);
    lines.push(detail(
        "summary",
        &fit(&model.summary, value_width(area, 10)),
    ));
    append_strategy_queue_rows(&mut lines, &model, area);
    lines.push(blank());
    lines.push(command_list_line(&model.commands, area.width as usize));
    lines
}

fn append_strategy_queue_details(lines: &mut Vec<Line<'static>>, model: &StrategyQueueModel) {
    for row in &model.detail_rows {
        lines.push(detail(&row.cells[0], &row.cells[1]));
    }
}

fn append_strategy_queue_rows(
    lines: &mut Vec<Line<'static>>,
    model: &StrategyQueueModel,
    area: Rect,
) {
    lines.push(blank());
    if model.rows.is_empty() {
        append_strategy_queue_empty(lines, model);
        return;
    }
    let widths = strategy_queue_widths(area.width);
    lines.push(table_header(&model.headers, &widths));
    for row in &model.rows {
        lines.extend(strategy_queue_row_lines(row, &widths, area.width));
    }
}

fn append_strategy_queue_empty(lines: &mut Vec<Line<'static>>, model: &StrategyQueueModel) {
    lines.extend(empty_state_panel(
        model.empty_state.title,
        &model.empty_state.explanations,
        &model.empty_state.actions,
    ));
}

fn strategy_queue_row_lines(
    row: &StrategyQueueRow,
    widths: &[usize],
    width: u16,
) -> Vec<Line<'static>> {
    let cells = fitted_strategy_cells(row, widths);
    let refs = cells.iter().map(String::as_str).collect::<Vec<_>>();
    let mut lines = vec![table_row(&refs, widths)];
    lines.push(detail(
        "lineage",
        &fit(&row.lineage, value_width_rect(width)),
    ));
    lines.push(detail("why", &fit(&row.rationale, value_width_rect(width))));
    lines.push(detail(
        "source run",
        &fit(&row.source_run, value_width_rect(width)),
    ));
    lines
}

fn fitted_strategy_cells(row: &StrategyQueueRow, widths: &[usize]) -> Vec<String> {
    row.cells
        .iter()
        .zip(widths.iter())
        .map(|(cell, width)| fit(cell, *width))
        .collect()
}

fn strategy_queue_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    if total < 110 {
        return vec![8, 7, 10, 18, 6, 6, 8, 8, 12, 10, 10, 8];
    }
    vec![10, 8, 14, 22, 7, 7, 10, 10, 16, 11, 12, 9]
}

fn value_width_rect(width: u16) -> usize {
    width.saturating_sub(20) as usize
}
