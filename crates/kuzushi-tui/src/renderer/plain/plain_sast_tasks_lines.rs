use super::*;
use crate::ui_view_models::{
    plain_help_model, plain_sast_tasks_model, PlainHelpCategoryModel, PlainHelpModel,
    PlainSastTaskRow, PlainSastTasksModel,
};

pub(crate) fn plain_sast_tasks_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_sast_tasks_model(app);
    push_plain_sast_tasks_summary(&mut lines, &model, width);
    push_plain_sast_tasks_table(&mut lines, &model, width);
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
    lines
}

fn push_plain_sast_tasks_summary(
    lines: &mut Vec<String>,
    model: &PlainSastTasksModel,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
}

fn push_plain_sast_tasks_table(lines: &mut Vec<String>, model: &PlainSastTasksModel, width: usize) {
    lines.push(String::new());
    let widths = sast_task_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(&model.headers, &widths));
    for row in &model.rows {
        lines.push(plain_sast_task_row(row, &widths));
    }
}

fn plain_sast_task_row(row: &PlainSastTaskRow, widths: &[usize]) -> String {
    let [state, id, cost, scan_task, notes] = &row.cells;
    table_text(
        &[
            state,
            id,
            cost,
            scan_task,
            &fit(notes, widths.get(4).copied().unwrap_or(20)),
        ],
        widths,
    )
}

pub(crate) fn plain_help_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_help_model(app.router.help().filter());
    push_plain_help_summary(&mut lines, &model, width);
    for category in &model.categories {
        append_plain_help_category(&mut lines, category);
    }
    lines
}

fn push_plain_help_summary(lines: &mut Vec<String>, model: &PlainHelpModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.push(model.intro.to_string());
    lines.push(model.glossary.to_string());
    if let Some(note) = &model.filter_note {
        lines.push(note.clone());
    }
    if let Some(examples) = &model.examples_line {
        lines.push(examples.clone());
    }
}

fn append_plain_help_category(lines: &mut Vec<String>, category: &PlainHelpCategoryModel) {
    lines.push(String::new());
    lines.push(category.heading.clone());
    lines.extend(category.rows.iter().cloned());
}
