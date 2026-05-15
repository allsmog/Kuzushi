use super::*;
use crate::ui_view_models::{help_model, HelpCategoryModel, HelpCommandRow};

pub(crate) fn plain_sast_tasks_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = crate::ui_view_models::sast_tasks_model(app);

    lines.push(String::new());
    lines.push(plain_section_divider("SAST TASKS", width));
    lines.push(format!("mode: {}", model.mode_label));
    lines.push(format!("selected: {}", model.selected_summary));
    lines.push(String::new());
    let widths = sast_task_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(
        &["state", "id", "cost", "scan", "notes"],
        &widths,
    ));
    for row in model.rows {
        lines.push(table_text(
            &[
                row.state,
                row.id,
                row.cost,
                row.scan_task,
                &fit(row.notes, widths.get(4).copied().unwrap_or(20)),
            ],
            &widths,
        ));
    }
    lines.push(String::new());
    lines.push(
        "Next: task block <id>, task allow <id>, task toggle [id], task mode auto|manual|toggle"
            .to_string(),
    );
    lines
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
