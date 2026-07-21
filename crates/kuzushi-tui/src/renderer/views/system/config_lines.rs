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
    fit_table_widths(area.width as usize, [2, 2, 28, 6, 40], [1, 1, 10, 3, 6])
}

fn config_model_row(row: &ConfigModelRow, widths: &[usize]) -> Line<'static> {
    aligned_row(&row.cells, widths)
}

fn push_config_commands(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(command_list_line(&model.commands, area.width as usize));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_columns_fit_narrow_area_budgets() {
        let row = ConfigModelRow {
            cells: [
                ">".to_string(),
                "1".to_string(),
                "openai:日本語-model".to_string(),
                "xhigh".to_string(),
                "authenticated through a long credential label".to_string(),
            ],
        };
        for width in [40, 60, 80] {
            let widths = config_model_widths(Rect::new(0, 0, width, 20));
            let line = config_model_row(&row, &widths);
            let rendered_width = line
                .spans
                .iter()
                .map(|span| display_width(span.content.as_ref()))
                .sum::<usize>();

            assert_eq!(table_width(&widths), width as usize);
            assert!(rendered_width <= width as usize);
        }
    }
}
