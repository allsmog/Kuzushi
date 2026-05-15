use super::*;
use crate::ui_view_models::{options_model, OptionRow, OptionsModelStatus};

pub(crate) fn plain_options_lines(
    app: &ShellApp,
    width: usize,
    view: &crate::app::OptionsView,
) -> Vec<String> {
    let model = options_model(app, view);
    let mut lines = plain_context_strip(app, width);
    lines.push(String::new());
    lines.push(plain_section_divider("OPTIONS", width));
    lines.push(format!("tool: {}", model.tool_name));
    lines.push(format!("view: {}", model.filter_label));
    push_plain_options_body(&mut lines, width, &model.status, &model.rows);
    lines
}

fn push_plain_options_body(
    lines: &mut Vec<String>,
    width: usize,
    status: &OptionsModelStatus,
    rows: &[OptionRow],
) {
    match status {
        OptionsModelStatus::Ready => push_plain_options_table(lines, width, rows),
        OptionsModelStatus::UnknownTool => {
            lines.push(String::new());
            lines.push("Unknown tool. Next: tools".to_string());
        }
        OptionsModelStatus::Empty { plain_message, .. } => {
            lines.push(String::new());
            lines.push((*plain_message).to_string());
        }
    }
}

fn push_plain_options_table(lines: &mut Vec<String>, width: usize, rows: &[OptionRow]) {
    lines.push(String::new());
    let widths = option_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(
        table_text(
            &[
                "option",
                "value",
                "default",
                "req",
                "type",
                "aliases",
                "description",
            ],
            &widths,
        )
        .trim_end()
        .to_string(),
    );
    for row in rows {
        lines.push(plain_option_row(row, &widths));
    }
    lines.push(String::new());
    lines.push(
        "Canonical keys are in the option column; aliases are compatibility names.".to_string(),
    );
    lines.push(
        "Next: set <key> <value>, setg <key> <value>, show advanced, show missing".to_string(),
    );
}

fn plain_option_row(row: &OptionRow, widths: &[usize]) -> String {
    table_text(
        &[
            &row.name,
            &row.value,
            &row.default_value,
            row.required,
            row.option_type,
            &fit(&row.aliases, widths.get(5).copied().unwrap_or(10)),
            &fit(&row.description, widths.get(6).copied().unwrap_or(16)),
        ],
        widths,
    )
    .trim_end()
    .to_string()
}
