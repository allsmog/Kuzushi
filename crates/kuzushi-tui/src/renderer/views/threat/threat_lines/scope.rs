use super::*;
use crate::ui_view_models::ThreatScopeTone;

pub(super) fn append_scope_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let model = crate::ui_view_models::threat_scope_model(app);
    lines.push(section_header_line(&model.header, area.width));
    for bucket in &model.buckets {
        append_scope_bucket(bucket, lines);
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
    bucket: &crate::ui_view_models::ThreatScopeBucket,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(bucket.header.clone(), threat_scope_tone_style(bucket.tone)),
    ]));
    for item in &bucket.visible_items {
        lines.push(Line::from(vec![
            Span::raw("      "),
            Span::styled("• ", theme::subtle()),
            Span::styled(item.clone(), theme::muted()),
        ]));
    }
    if let Some(overflow) = &bucket.overflow_label {
        lines.push(Line::from(vec![
            Span::raw("      "),
            Span::styled(overflow.clone(), theme::subtle()),
        ]));
    }
}

fn threat_scope_tone_style(tone: ThreatScopeTone) -> Style {
    match tone {
        ThreatScopeTone::Critical => theme::severity(Severity::Critical),
        ThreatScopeTone::High => theme::severity(Severity::High),
        ThreatScopeTone::Medium => theme::severity(Severity::Medium),
        ThreatScopeTone::Low => theme::severity(Severity::Low),
        ThreatScopeTone::Info => theme::severity(Severity::Info),
        ThreatScopeTone::Unknown => theme::severity(Severity::Unknown),
    }
}
