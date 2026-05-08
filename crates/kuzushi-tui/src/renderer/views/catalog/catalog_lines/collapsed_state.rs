use super::*;

pub(super) fn append_collapsed_catalog(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    if app.target.is_none() {
        lines.push(styled(
            "[!] no target selected; `scan .` uses the current directory",
            theme::warn(),
        ));
    } else if app.findings.is_empty() {
        lines.push(styled(
            "[!] active target has no persisted findings yet",
            theme::warn(),
        ));
    }
    lines.push(next_action_line(
        &catalog_next_hint(app),
        area.width as usize,
    ));
    if app.findings.is_empty() {
        lines.push(muted(&fit(&app.first_finding_hint(), area.width as usize)));
    }
    if area.width < 96 {
        lines.push(Line::from(vec![
            Span::styled("Start here: ", theme::muted()),
            Span::styled("kuzushi doctor --target .", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("context build", theme::accent()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Then: ", theme::muted()),
            Span::styled(app.first_finding_scan_command(), theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("findings", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("pr-comment", theme::accent()),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Start here: ", theme::muted()),
            Span::styled("kuzushi doctor --target .", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("context build", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled(app.first_finding_scan_command(), theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("findings", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("pr-comment", theme::accent()),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Quickstart: ", theme::muted()),
        Span::styled("quickstart", theme::accent()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("Context: ", theme::muted()),
        Span::styled("context build", theme::accent()),
        Span::styled(" · ", theme::subtle()),
        Span::styled("Runtime: ", theme::muted()),
        Span::styled("model", theme::accent()),
    ]));
    lines.push(muted(
        "Type help, modules, use <module>, scan, or run <tool> [json].",
    ));
}
