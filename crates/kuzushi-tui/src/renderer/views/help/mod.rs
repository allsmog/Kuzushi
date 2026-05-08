pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

pub(crate) fn help_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HELP", area.width));
    lines.push(muted(&fit(
        "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode.",
        area.width as usize,
    )));
    let examples = shell_help_examples();
    if !examples.is_empty() {
        lines.push(muted(&fit(
            &format!("Examples: {}", examples.join(" | ")),
            area.width as usize,
        )));
    }
    let widths = help_table_widths(area.width);
    for category in ShellCommandCategory::ORDER {
        lines.push(blank());
        lines.push(category_divider(
            category.label(),
            help_category_blurb(category),
            area.width,
        ));
        for spec in shell_command_specs().filter(|spec| spec.category == category) {
            let command = fit(spec.command, widths.first().copied().unwrap_or(18));
            let aliases = help_alias_text(spec, widths.get(1).copied().unwrap_or(18));
            if widths.len() == 2 {
                lines.push(table_row(&[&command, &aliases], &widths));
            } else {
                let description = fit(spec.description, widths.get(2).copied().unwrap_or(20));
                lines.push(table_row(&[&command, &aliases, &description], &widths));
            }
        }
    }
    lines
}

/// Section blurbs for the `/help` view, aligned with `design/mockups/help.jsx::sec`.
pub(crate) fn help_category_blurb(category: ShellCommandCategory) -> &'static str {
    match category {
        ShellCommandCategory::Navigation => "browse modules and tools",
        ShellCommandCategory::RunScan => "dispatch tools and scans",
        ShellCommandCategory::OptionsTasks => "options + sast task control",
        ShellCommandCategory::ContextKb => "workspace + attachments",
        ShellCommandCategory::FindingsEvidence => "browse findings, evidence, and report output",
        ShellCommandCategory::AuthConfigModel => "auth, model, runtime config",
        ShellCommandCategory::Session => "history, cost, lifecycle",
    }
}

pub(crate) fn quickstart_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("QUICKSTART", area.width));
    lines.push(blank());
    lines.push(Line::styled(
        "Welcome to kuzushi. Operator path:",
        theme::heading(),
    ));
    lines.push(blank());
    let scan_step = if app.target.is_some() {
        "scan / run                 scan the active target; run <tool> dispatches one tool"
    } else {
        "scan . / run <tool>        scan this directory; run <tool> dispatches one tool"
    };
    let steps = [
        (
            "1",
            "doctor                    CLI preflight: kuzushi doctor",
        ),
        (
            "2",
            "context build              write .kuzushi/context-snapshot.json",
        ),
        ("3", scan_step),
        (
            "4",
            "findings / open F-0001     inspect evidence and proof state",
        ),
        (
            "5",
            "report output              workspace export; kuzushi pr-comment",
        ),
    ];
    for (num, step) in steps {
        lines.push(Line::from(vec![
            Span::styled(format!("  {num}. "), theme::accent()),
            Span::styled(
                fit(step, area.width.saturating_sub(5) as usize),
                theme::primary(),
            ),
        ]));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "Tip: Ctrl+O toggles the live event timeline.",
        area.width as usize,
    )));
    lines.push(muted(&fit(
        &format!(
            "First-finding path: `{}` then `findings`.",
            app.first_finding_scan_command()
        ),
        area.width as usize,
    )));
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

pub(crate) fn help_alias_text(spec: &ShellCommandSpec, max_chars: usize) -> String {
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
        fit(&aliases.join(", "), max_chars)
    }
}
