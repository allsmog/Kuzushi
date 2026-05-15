use super::*;
use crate::ui_view_models::threat_nav_model;

pub(crate) fn threat_nav(active: ThreatView) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, item) in threat_nav_model(active).iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        let style = if item.active {
            theme::selection()
        } else {
            theme::muted()
        };
        spans.push(Span::styled(item.label, style));
    }
    Line::from(spans)
}

pub(crate) fn stride_row(
    letter: &str,
    severity: Severity,
    category: &str,
    count: usize,
    description: &str,
    width: u16,
) -> Line<'static> {
    let total = width as usize;
    let used = 3 + 3 + 1 + 16 + 4 + 10;
    let desc_w = total.saturating_sub(used).max(8);
    let issues_label = if count == 1 { "issue" } else { "issues" };
    let mut spans = vec![
        Span::raw("   "),
        Span::styled(format!(" {letter} "), theme::severity(severity)),
        Span::raw(" "),
        Span::styled(pad(category, 16), theme::muted()),
        Span::styled(format!("{count} "), theme::primary()),
        Span::styled(format!("{issues_label}"), theme::muted()),
    ];
    if !description.is_empty() {
        spans.push(Span::styled("  · ", theme::muted()));
        spans.push(Span::styled(fit(description, desc_w), theme::muted()));
    }
    Line::from(spans)
}
