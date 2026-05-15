use super::*;
use crate::ui_view_models::{
    help_model, plain_sast_tasks_model, HelpCategoryModel, HelpCommandRow, PlainSastTaskRow,
    PlainSastTasksModel,
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
    table_text(
        &[
            row.state,
            row.id,
            row.cost,
            row.scan_task,
            &fit(row.notes, widths.get(4).copied().unwrap_or(20)),
        ],
        widths,
    )
}

pub(crate) fn plain_help_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = help_model();
    lines.push(String::new());
    lines.push(plain_section_divider("HELP", width));
    lines.push(model.intro.to_string());
    if !model.examples.is_empty() {
        lines.push(format!("Examples: {}", model.examples.join(" | ")));
    }

    for category in &model.categories {
        append_plain_help_category(&mut lines, category);
    }

    lines
}

fn append_plain_help_category(lines: &mut Vec<String>, category: &HelpCategoryModel) {
    lines.push(String::new());
    lines.push(format!("{} — {}", category.label, category.blurb));
    for row in &category.commands {
        append_plain_help_spec(lines, row);
    }
}

fn append_plain_help_spec(lines: &mut Vec<String>, row: &HelpCommandRow) {
    lines.push(format!("{} - {}", row.command, row.description));
    if row.aliases != "-" {
        lines.push(format!("  aliases / examples: {}", row.aliases));
    }
}
