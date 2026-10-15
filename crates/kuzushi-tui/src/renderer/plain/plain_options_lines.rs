use super::*;
use crate::ui_view_models::{
    plain_options_model, PlainOptionRow, PlainOptionsBody, PlainOptionsModel, PlainOptionsTable,
};

pub(crate) fn plain_options_lines(
    app: &ShellApp,
    width: usize,
    view: &crate::app::OptionsView,
) -> Vec<String> {
    if let Some(snapshot) = app.options_screen_snapshot() {
        return plain_options_snapshot_lines(snapshot.clone(), width);
    }
    if let Some(edit) = app.router.options_browser().edit.as_ref() {
        return plain_option_editor(edit, width);
    }

    let model = plain_options_model(app, view);
    let mut lines = plain_context_strip(app, width);
    push_plain_options_summary(&mut lines, &model, width);
    push_plain_options_body(&mut lines, width, &model.body);
    lines
}

fn plain_option_editor(edit: &crate::app::ToolOptionEdit, width: usize) -> Vec<String> {
    let scope = if edit.global { "global" } else { "session" };
    let mut lines = vec![format!("EDIT {}.{} · {scope}", edit.tool, edit.option)];
    lines.extend(
        crate::renderer::shared::field_editor_lines(&edit.field, width, usize::MAX)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect()
            }),
    );
    lines.extend(edit.error.iter().cloned());
    lines.push("Enter/Ctrl+S save · Ctrl+G global · Esc keeps draft".into());
    lines
}

fn plain_options_snapshot_lines(snapshot: OptionsScreenSnapshot, width: usize) -> Vec<String> {
    let mut lines = vec![
        format!(
            " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
            snapshot.status.target,
            snapshot.status.ctx,
            snapshot.status.model,
            snapshot.status.module,
            snapshot.status.cost
        ),
        "─".repeat(width),
        String::new(),
    ];
    lines.extend(snapshot.body_rows);
    lines.push(String::new());
    lines.push("─".repeat(width));
    lines.push(options_footer_stage_line(width, &snapshot.footer));
    lines.push(options_footer_keybind_line(&snapshot.footer));
    lines.push(match snapshot.footer.prompt_module {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    });
    lines
}

fn options_footer_stage_line(width: usize, footer: &OptionsScreenFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn options_footer_keybind_line(footer: &OptionsScreenFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
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
    let aliases = fit(&row.cells[5], widths.get(5).copied().unwrap_or(10));
    let description = fit(&row.cells[6], widths.get(6).copied().unwrap_or(16));
    table_text(
        &[
            &row.cells[0],
            &row.cells[1],
            &row.cells[2],
            &row.cells[3],
            &row.cells[4],
            &aliases,
            &description,
        ],
        widths,
    )
    .trim_end()
    .to_string()
}
