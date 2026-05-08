use super::*;

pub(crate) fn catalog_next_hint(app: &ShellApp) -> String {
    if !app.context_view.exists {
        return "Build the context snapshot with `context build` so SAST has structure to walk."
            .to_string();
    }
    let critical_count = app
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    if critical_count > 0 {
        if let Some((alias, _)) = sorted_finding_aliases(&app.findings).into_iter().next() {
            return format!(
                "Drill in: `open {alias}` for the highest-severity finding · `findings` for the list."
            );
        }
    }
    if !app.findings.is_empty() {
        return format!(
            "{} finding(s) waiting · `findings` to triage · `threats regen` for STRIDE refresh.",
            app.findings.len()
        );
    }
    app.first_finding_hint()
}

pub(crate) fn catalog_module_row(
    id: &str,
    description: &str,
    focused: bool,
    widths: &[usize],
) -> Line<'static> {
    let id_width = widths.first().copied().unwrap_or(16);
    let description_width = widths.get(1).copied().unwrap_or(24);
    if focused {
        return Line::from(vec![
            Span::styled("▌ ", theme::accent()),
            Span::styled(
                format!(
                    "{}  {}",
                    pad(id, id_width),
                    pad(description, description_width)
                ),
                theme::selection(),
            ),
        ]);
    }
    Line::from(vec![
        Span::raw("  "),
        Span::styled(pad(id, id_width), theme::primary()),
        Span::raw("  "),
        Span::styled(pad(description, description_width), theme::muted()),
    ])
}

pub(crate) fn tool_console_row(
    name: &str,
    description: &str,
    headless: bool,
    width: u16,
) -> Line<'static> {
    let status = if headless { "headless" } else { "interactive" };
    let name_width = if width < 80 { 22 } else { 30 };
    let used = 4 + name_width + status.len() + 6;
    Line::from(vec![
        Span::styled(" ⏵ ", theme::subtle()),
        Span::styled(pad(name, name_width), theme::accent()),
        Span::styled(format!(" {status} "), theme::muted()),
        Span::styled(
            fit(description, (width as usize).saturating_sub(used).max(12)),
            theme::primary(),
        ),
    ])
}
