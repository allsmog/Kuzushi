use super::*;
use crate::ui_view_models::{config_model, ConfigModel, ConfigModelRow, ConfigSummaryRow};

pub(crate) fn config_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = config_model(app);
    push_config_summary(&mut lines, &model, area);
    push_config_model_table(&mut lines, &model, area);
    push_config_commands(&mut lines, area);
    lines
}

fn push_config_summary(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(divider(model.summary_title, area.width));
    for row in &model.summary_rows {
        lines.push(config_summary_row(row));
    }
}

fn config_summary_row(row: &ConfigSummaryRow) -> Line<'static> {
    detail(row.label, &row.value)
}

fn push_config_model_table(lines: &mut Vec<Line<'static>>, model: &ConfigModel, area: Rect) {
    lines.push(blank());
    lines.push(divider("MODELS", area.width));
    let widths = config_model_widths(area);
    lines.push(aligned_header(
        &["", "#", "model", "effort", "auth"],
        &widths,
    ));
    for row in &model.model_rows {
        lines.push(config_model_row(row, &widths));
    }
}

fn config_model_widths(area: Rect) -> [usize; 5] {
    [2usize, 2, 28, 6, value_width(area, 28)]
}

fn config_model_row(row: &ConfigModelRow, widths: &[usize]) -> Line<'static> {
    let marker = if row.selected { ">" } else { " " };
    aligned_row(
        &[
            marker.to_string(),
            row.index.clone(),
            row.model.clone(),
            row.effort.clone(),
            row.auth.clone(),
        ],
        widths,
    )
}

fn push_config_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "Up/Down select",
            "Enter choose",
            "model <n> [xhigh]",
            "auth login openai|anthropic",
        ],
        area.width as usize,
    ));
}
