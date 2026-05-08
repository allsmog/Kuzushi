pub(in crate::renderer) use super::*;

pub(crate) fn module_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = if total < 72 { 14 } else { 22 };
    let gaps = 2;
    let description = total.saturating_sub(id + gaps).max(16);
    vec![id, description]
}

pub(crate) fn table_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    // Mockup column headers wear `c-label` (bold blue), see e.g.
    // `design/mockups/findings.jsx::heads` and `tools.jsx::heads`.
    Line::styled(table_text(values, widths), theme::label())
}

pub(crate) fn table_row(values: &[&str], widths: &[usize]) -> Line<'static> {
    // Same colour split as `aligned_row` so help/options/findings tables
    // share the mockup tint:
    //   col 0 → c-accent (identifier), middle → c-primary, last → c-muted
    let mut spans = Vec::new();
    let last = values.len().saturating_sub(1);
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("  "));
        }
        let style = if index == 0 {
            theme::accent()
        } else if values.len() > 2 && index == last {
            theme::muted()
        } else {
            theme::primary()
        };
        spans.push(Span::styled(
            pad(value, widths.get(index).copied().unwrap_or(12)),
            style,
        ));
    }
    Line::from(spans)
}

pub(crate) fn table_text(values: &[&str], widths: &[usize]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| pad(value, widths.get(index).copied().unwrap_or(12)))
        .collect::<Vec<_>>()
        .join("  ")
}

pub(crate) fn row(values: &[String]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let style = if index == 0 {
                    theme::accent()
                } else {
                    Style::default()
                };
                Span::styled(format!("{}  ", value), style)
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn aligned_header(values: &[&str], widths: &[usize]) -> Line<'static> {
    Line::from(
        values
            .iter()
            .zip(widths.iter())
            .map(|(value, width)| {
                // c-label header per `design/mockups/_shared.jsx` headers.
                Span::styled(format!("{}  ", pad(value, *width)), theme::label())
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn aligned_row(values: &[String], widths: &[usize]) -> Line<'static> {
    // Mockup table rows (`design/mockups/tools.jsx`, `modules.jsx`,
    // `cost.jsx`, etc.) consistently put the first column (the
    // identifier) in c-accent, with subsequent value columns in
    // c-primary and metadata columns (last when present) in c-muted.
    // The Ratatui `aligned_row` was leaving columns 1+ in
    // `Style::default()`, which renders as terminal default white —
    // visibly distinct from the mockup's softer c-primary tint.
    let last = values.len().saturating_sub(1);
    Line::from(
        values
            .iter()
            .zip(widths.iter())
            .enumerate()
            .map(|(index, (value, width))| {
                let style = if index == 0 {
                    theme::accent()
                } else if values.len() > 2 && index == last {
                    theme::muted()
                } else {
                    theme::primary()
                };
                Span::styled(format!("{}  ", pad(&fit(value, *width), *width)), style)
            })
            .collect::<Vec<_>>(),
    )
}
