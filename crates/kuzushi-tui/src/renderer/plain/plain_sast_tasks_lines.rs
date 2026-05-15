use super::*;

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
    lines.push(String::new());
    lines.push(plain_section_divider("HELP", width));
    lines.push(
        "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode."
            .to_string(),
    );
    let examples = shell_help_examples();
    if !examples.is_empty() {
        lines.push(format!("Examples: {}", examples.join(" | ")));
    }

    for category in ShellCommandCategory::ORDER {
        append_plain_help_category(&mut lines, category);
    }

    lines
}

fn append_plain_help_category(lines: &mut Vec<String>, category: ShellCommandCategory) {
    lines.push(String::new());
    lines.push(format!(
        "{} — {}",
        category.label(),
        help_category_blurb(category)
    ));
    for spec in shell_command_specs().filter(|spec| spec.category == category) {
        append_plain_help_spec(lines, spec);
    }
}

fn append_plain_help_spec(lines: &mut Vec<String>, spec: &ShellCommandSpec) {
    lines.push(format!("{} - {}", spec.command, spec.description));
    let aliases = plain_help_alias_text(spec);
    if aliases != "-" {
        lines.push(format!("  aliases / examples: {aliases}"));
    }
}

pub(crate) fn plain_help_alias_text(spec: &ShellCommandSpec) -> String {
    let mut aliases = Vec::new();
    for alias in spec.aliases {
        if *alias == spec.command || aliases.contains(alias) {
            continue;
        }
        aliases.push(*alias);
    }
    if aliases.is_empty() {
        "-".to_string()
    } else {
        aliases.join(", ")
    }
}
