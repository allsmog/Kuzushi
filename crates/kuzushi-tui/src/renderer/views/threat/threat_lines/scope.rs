use super::*;

pub(super) fn append_scope_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let doc = current_threat_model_doc(app);
    let buckets = doc
        .as_ref()
        .and_then(scope_buckets_from_doc)
        .unwrap_or_else(canonical_scope_buckets);
    let total: usize = buckets.iter().map(|(_, _, items)| items.len()).sum();
    lines.push(section_header_line(
        &format!("SCOPE · {total} issues"),
        area.width,
    ));
    for (severity, label, items) in &buckets {
        append_scope_bucket(*severity, label, items, lines);
    }
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled("OUT OF SCOPE", theme::muted()),
    ]));
    lines.push(Line::from(vec![
        Span::raw("      "),
        Span::styled("• ", theme::subtle()),
        Span::styled("generated caches, vendored fixtures", theme::muted()),
    ]));
}

fn append_scope_bucket(
    severity: Severity,
    label: &str,
    items: &[String],
    lines: &mut Vec<Line<'static>>,
) {
    if items.is_empty() {
        return;
    }
    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(
            format!("{} · {}", label.to_uppercase(), items.len()),
            theme::severity(severity),
        ),
    ]));
    for item in items.iter().take(4) {
        lines.push(Line::from(vec![
            Span::raw("      "),
            Span::styled("• ", theme::subtle()),
            Span::styled(item.clone(), theme::muted()),
        ]));
    }
    if items.len() > 4 {
        lines.push(Line::from(vec![
            Span::raw("      "),
            Span::styled(format!("… {} more", items.len() - 4), theme::subtle()),
        ]));
    }
}
