use super::*;
use crate::ui_view_models::{
    config_model, ConfigModel, ConfigModelRow, ConfigModelTable, ConfigSummaryRow,
};

pub(crate) fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = config_model(app);
    push_config_summary(&mut lines, &model, area);
    push_config_model_table(&mut lines, &model, area);
    push_config_commands(&mut lines, &model, area);
    lines
}

fn push_config_summary(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(divider(model.summary_title, area.width));
    for row in &model.summary_rows {
        lines.extend(config_summary_row(row, area.width));
    }
}

fn config_summary_row(row: &ConfigSummaryRow, width: u16) -> Vec<Line<'static>> {
    // Several config values run long (auth env summary, oauth status,
    // build provenance) — wrap them under the key column.
    detail_wrapped(&row.cells[0], &row.cells[1], width)
}

fn push_config_model_table(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(config_model_table_title(&model.model_table, area.width));
    let widths = config_model_widths(area);
    lines.push(aligned_header(&model.model_table.headers, &widths));
    for row in &model.model_table.rows {
        lines.push(config_model_row(row, &widths));
    }
}

fn config_model_table_title(table: &ConfigModelTable, width: u16) -> Line<'static> {
    divider(table.title, width)
}

fn config_model_widths(area: Rect) -> [usize; 5] {
    [2usize, 2, 28, 6, value_width(area, 28)]
}

fn config_model_row(row: &ConfigModelRow, widths: &[usize]) -> Line<'static> {
    aligned_row(&row.cells, widths)
}

fn push_config_commands(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(command_list_line(&model.commands, area.width as usize));
}
