use super::*;

pub(super) fn append_scope_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let buckets = crate::ui_view_models::threat_scope_buckets(app);
    let total: usize = buckets.iter().map(|bucket| bucket.items.len()).sum();
    lines.push(section_header_line(
        &format!("SCOPE · {total} issues"),
        area.width,
    ));
    for bucket in &buckets {
        append_scope_bucket(bucket.severity, bucket.label, &bucket.items, lines);
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
