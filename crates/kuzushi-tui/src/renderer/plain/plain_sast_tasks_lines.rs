use super::*;

pub(crate) fn plain_sast_tasks_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let rows = app.sast_task_rows();
    let enabled = rows.iter().filter(|row| row.selected).count();
    let blocked = rows.iter().filter(|row| row.source == "blocked").count();
    let mode = app
        .option_store
        .effective_stored_values("sast:scan")
        .get("taskMode")
        .and_then(serde_json::Value::as_str)
        .filter(|mode| *mode == "manual")
        .map(|_| "manual allowlist")
        .unwrap_or("auto + denylist");

    lines.push(String::new());
    lines.push(plain_section_divider("SAST TASKS", width));
    lines.push(format!("mode: {mode}"));
    lines.push(format!(
        "selected: {enabled}/{} enabled, {blocked} blocked",
        rows.len()
    ));
    lines.push(String::new());
    let widths = sast_task_table_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(
        &["state", "id", "cost", "scan", "notes"],
        &widths,
    ));
    for row in rows {
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
        lines.push(String::new());
        // Mirror the `category_divider` from the Ratatui renderer in plain
        // text: section name followed by the design-mockup blurb on one line.
        lines.push(format!(
            "{} — {}",
            category.label(),
            help_category_blurb(category)
        ));
        for spec in shell_command_specs().filter(|spec| spec.category == category) {
            lines.push(format!("{} - {}", spec.command, spec.description));
            let aliases = plain_help_alias_text(spec);
            if aliases != "-" {
                lines.push(format!("  aliases / examples: {aliases}"));
            }
        }
    }

    lines
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
