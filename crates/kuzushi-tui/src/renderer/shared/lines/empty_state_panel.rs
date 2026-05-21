use super::*;

pub(crate) fn empty_state_panel(
    glyph_label: &str,
    explanations: &[&str],
    ctas: &[(&str, &str)],
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::raw("       "),
        Span::styled("∅  ", theme::subtle()),
        Span::styled(glyph_label.to_string(), theme::muted()),
    ]));
    for explanation in explanations {
        lines.push(Line::from(vec![
            Span::raw("       "),
            Span::styled((*explanation).to_string(), theme::muted()),
        ]));
    }
    if !ctas.is_empty() {
        lines.push(blank());
    }
    for (cmd, blurb) in ctas {
        // 22-char command pad keeps the blurbs visually aligned across
        // CTA rows (matches the mockup's fixed indent + spacing).
        let cmd_padded = if cmd.chars().count() >= 22 {
            format!("{cmd}  ")
        } else {
            format!("{cmd}{}", " ".repeat(22 - cmd.chars().count()))
        };
        lines.push(Line::from(vec![
            Span::raw("       "),
            Span::styled("▸ ", theme::warn()),
            Span::styled(cmd_padded, theme::accent()),
            Span::styled((*blurb).to_string(), theme::muted()),
        ]));
    }
    lines
}

pub(crate) fn command_list_line(commands: &[&str], width: usize) -> Line<'static> {
    let prefix = "▸ try: ";
    let mut spans: Vec<Span<'static>> = vec![Span::styled(prefix.to_string(), theme::muted())];
    let mut used = prefix.chars().count();
    for (i, cmd) in commands.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ".to_string(), theme::subtle()));
            used += 3;
        }
        let cmd_chars = cmd.chars().count();
        if used + cmd_chars > width {
            spans.push(Span::styled("…".to_string(), theme::subtle()));
            break;
        }
        spans.push(Span::styled((*cmd).to_string(), theme::accent()));
        used += cmd_chars;
    }
    Line::from(spans)
}

pub(crate) fn indent(line: Line<'static>, spaces: usize) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(spaces))];
    spans.extend(line.spans);
    Line::from(spans)
}

pub(crate) fn next_action_line(text: &str, width: usize) -> Line<'static> {
    let available = width.saturating_sub(8);
    let fitted = fit(text, available);
    // Mirror the mockup's c-warn / c-primary / c-accent / c-muted split for
    // the catalog NEXT line (see `design/mockups/catalog.jsx`):
    //   ▸ NEXT  Run sast:scan against ~/work/acme-checkout — never run …
    //   ----    --- --------- ----------------------------- -------------
    //   warn    pri accent    primary                       muted
    // Tool name accent: detect a `Run <tool> ` prefix and split off the
    // identifier so an operator's eye lands on the actual command they're
    // about to dispatch.  Em-dash split: any ambient context after ` — `
    // (run history, finding count) reads softer than the imperative.
    let mut spans: Vec<Span<'static>> = vec![Span::styled("▸ NEXT ", theme::warn())];

    // Split at em-dash first so the muted suffix is always its own span.
    let (head, tail_with_dash) = match fitted.find(" — ") {
        Some(idx) => (&fitted[..idx], Some(&fitted[idx..])),
        None => (fitted.as_str(), None),
    };

    // Within the imperative head, detect `Run <tool> ` and accent the tool.
    if let Some(rest) = head.strip_prefix("Run ") {
        if let Some(space_idx) = rest.find(' ') {
            let tool = &rest[..space_idx];
            let after = &rest[space_idx..];
            spans.push(Span::styled("Run ".to_string(), theme::primary()));
            spans.push(Span::styled(tool.to_string(), theme::accent()));
            spans.push(Span::styled(after.to_string(), theme::primary()));
        } else {
            // `Run <single-word>` with no trailing context — accent it all.
            spans.push(Span::styled("Run ".to_string(), theme::primary()));
            spans.push(Span::styled(rest.to_string(), theme::accent()));
        }
    } else {
        spans.push(Span::styled(head.to_string(), theme::primary()));
    }

    if let Some(tail) = tail_with_dash {
        spans.push(Span::styled(tail.to_string(), theme::muted()));
    }
    Line::from(spans)
}
