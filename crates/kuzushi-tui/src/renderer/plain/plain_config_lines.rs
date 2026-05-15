use super::*;
use crate::ui_view_models::{
    plain_config_model, plain_context_strip_model, PlainConfigModel, PlainConfigModelRow,
    PlainContextStripModel,
};

pub(crate) fn plain_config_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_config_model(app);
    push_plain_config_summary(&mut lines, &model, width);
    push_plain_model_table(&mut lines, &model, width);
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
    lines
}

fn push_plain_config_summary(lines: &mut Vec<String>, model: &PlainConfigModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.summary_title, width));
    lines.extend(model.summary_rows.iter().cloned());
}

fn push_plain_model_table(lines: &mut Vec<String>, model: &PlainConfigModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.model_table.title, width));
    lines.push(table_text(
        &model.model_table.headers,
        &plain_model_widths(width),
    ));
    let widths = plain_model_widths(width);
    for row in &model.model_table.rows {
        lines.push(plain_model_row(row, &widths));
    }
}

fn plain_model_row(row: &PlainConfigModelRow, widths: &[usize]) -> String {
    table_text(
        &[
            &row.cells[0],
            &fit(&row.cells[1], widths.get(1).copied().unwrap_or(28)),
            &row.cells[2],
            &fit(&row.cells[3], widths.get(3).copied().unwrap_or(18)),
        ],
        widths,
    )
}

pub(crate) fn plain_context_strip(app: &ShellApp, width: usize) -> Vec<String> {
    plain_context_strip_rows(plain_context_strip_model(app, width))
}

fn plain_context_strip_rows(model: PlainContextStripModel) -> Vec<String> {
    model.rows
}

pub(crate) fn plain_model_widths(width: usize) -> Vec<usize> {
    let number = 3;
    let effort = 6;
    let model = if width < 88 { 28 } else { 34 };
    let gaps = 6;
    let auth = width.saturating_sub(number + model + effort + gaps).max(14);
    vec![number, model, effort, auth]
}

pub(crate) fn plain_section_divider(title: &str, width: usize) -> String {
    // Mirror the styled `divider` from renderer.rs in plain text:
    //   ` ── TITLE ──────────────────...───`
    // Per `design/mockups/_shared.jsx::sectionHeader`. Use ASCII hyphen
    // for the rule so non-Unicode terminals/log scrapers don't choke on
    // the box-drawing char.
    let safe_width = width.max(8);
    let lead = "-- ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    format!(" {}{}{}", lead, label, "-".repeat(fill))
}

pub(crate) fn line_to_unstyled_text(line: Line<'static>) -> String {
    line.spans
        .into_iter()
        .map(|span| span.content.into_owned())
        .collect::<String>()
}
