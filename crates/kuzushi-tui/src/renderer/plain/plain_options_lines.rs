use super::*;
use crate::ui_view_models::{
    plain_options_model, PlainOptionRow, PlainOptionsBody, PlainOptionsModel, PlainOptionsTable,
};

pub(crate) fn plain_options_lines(
    app: &ShellApp,
    width: usize,
    view: &crate::app::OptionsView,
) -> Vec<String> {
    let model = plain_options_model(app, view);
    let mut lines = plain_context_strip(app, width);
    push_plain_options_summary(&mut lines, &model, width);
    push_plain_options_body(&mut lines, width, &model.body);
    lines
}

fn push_plain_options_summary(lines: &mut Vec<String>, model: &PlainOptionsModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
}

fn push_plain_options_body(lines: &mut Vec<String>, width: usize, body: &PlainOptionsBody) {
    match body {
        PlainOptionsBody::Table(table) => push_plain_options_table(lines, width, table),
        PlainOptionsBody::Message(rows) => {
            lines.push(String::new());
            lines.extend(rows.iter().cloned());
        }
    }
}

fn push_plain_options_table(lines: &mut Vec<String>, width: usize, table: &PlainOptionsTable) {
    lines.push(String::new());
    let widths = option_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(&table.headers, &widths).trim_end().to_string());
    for row in &table.rows {
        lines.push(plain_option_row(row, &widths));
    }
    lines.push(String::new());
    lines.push(table.note.to_string());
    lines.push(table.next_hint.to_string());
}

fn plain_option_row(row: &PlainOptionRow, widths: &[usize]) -> String {
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
