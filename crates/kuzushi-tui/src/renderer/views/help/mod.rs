use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::{help_model, quickstart_model, HelpCommandRow};

pub(crate) fn help_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = help_model();
    lines.push(blank());
    lines.push(divider("HELP", area.width));
    lines.push(muted(&fit(model.intro, area.width as usize)));
    if !model.examples.is_empty() {
        lines.push(muted(&fit(
            &format!("Examples: {}", model.examples.join(" | ")),
            area.width as usize,
        )));
    }
    let widths = help_table_widths(area.width);
    for category in &model.categories {
        lines.push(blank());
        lines.push(category_divider(category.label, category.blurb, area.width));
        for row in &category.commands {
            lines.push(help_command_line(row, &widths));
        }
    }
    lines
}

fn help_command_line(row: &HelpCommandRow, widths: &[usize]) -> Line<'static> {
    let command = fit(row.command, widths.first().copied().unwrap_or(18));
    let aliases = fit(&row.aliases, widths.get(1).copied().unwrap_or(18));
    if widths.len() == 2 {
        table_row(&[&command, &aliases], widths)
    } else {
        let description = fit(row.description, widths.get(2).copied().unwrap_or(20));
        table_row(&[&command, &aliases, &description], widths)
    }
}

pub(crate) fn quickstart_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = quickstart_model(app);
    lines.push(blank());
    lines.push(divider("QUICKSTART", area.width));
    lines.push(blank());
    lines.push(Line::styled(
        "Welcome to kuzushi. Operator path:",
        theme::heading(),
    ));
    lines.push(blank());
    for step in &model.steps {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}. ", step.number), theme::accent()),
            Span::styled(
                fit(step.text, area.width.saturating_sub(5) as usize),
                theme::primary(),
            ),
        ]));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "Tip: Ctrl+O toggles the live event timeline.",
        area.width as usize,
    )));
    lines.push(muted(&fit(&model.first_finding_tip, area.width as usize)));
    lines.push(blank());
    lines.push(muted(&fit(
        "Type `help` for the full command reference, or `back` to return.",
        area.width as usize,
    )));
    lines
}

pub(crate) fn help_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    if total < 72 {
        let command = total.min(if total < 48 { 14 } else { 18 });
        let aliases = total.saturating_sub(command + 2);
        return vec![command, aliases];
    }

    let command = if total < 96 { 22 } else { 28 };
    let aliases = if total < 96 { 24 } else { 32 };
    let description = total.saturating_sub(command + aliases + 4);
    vec![command, aliases, description]
}
