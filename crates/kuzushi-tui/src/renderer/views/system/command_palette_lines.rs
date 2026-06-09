use super::*;

const MAX_PALETTE_ROWS: usize = 12;

pub(crate) fn command_palette_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("COMMAND PALETTE", area.width));
    lines.push(query_line(app));
    lines.push(blank());
    push_match_rows(app, area, &mut lines);
    lines.push(blank());
    lines.push(Line::styled(
        "  ↑/↓ move · Enter load · Esc close",
        theme::muted(),
    ));
    lines
}

fn query_line(app: &ShellApp) -> Line<'static> {
    Line::from(vec![
        Span::styled("  > ", theme::accent()),
        Span::styled(app.palette_query.clone(), theme::primary()),
        Span::styled("▏", theme::accent()),
    ])
}

fn push_match_rows(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let matches = app.palette_matches();
    if matches.is_empty() {
        lines.push(Line::styled("  no matching commands", theme::muted()));
        return;
    }
    let desc_width = value_width(area, 40);
    for (idx, spec) in matches.iter().take(MAX_PALETTE_ROWS).enumerate() {
        lines.push(match_row(spec, desc_width, idx == app.palette_cursor));
    }
    if matches.len() > MAX_PALETTE_ROWS {
        lines.push(Line::styled(
            format!("  … {} more", matches.len() - MAX_PALETTE_ROWS),
            theme::subtle(),
        ));
    }
}

fn match_row(
    spec: &crate::commands::ShellCommandSpec,
    desc_width: usize,
    selected: bool,
) -> Line<'static> {
    let marker = if selected { "▌ " } else { "  " };
    let command = format!("{:<24}", fit(spec.command, 24));
    let description = fit(spec.description, desc_width);
    if selected {
        Line::from(vec![
            Span::styled(marker, theme::accent()),
            Span::styled(format!("{command}{description}"), theme::selection()),
        ])
    } else {
        Line::from(vec![
            Span::raw(marker),
            Span::styled(command, theme::primary()),
            Span::styled(description, theme::muted()),
        ])
    }
}
