use super::*;

pub(crate) fn threat_nav(active: ThreatView) -> Line<'static> {
    let items = [
        (ThreatView::Dfd, "1 DFD"),
        (ThreatView::Stride, "2 STRIDE"),
        (ThreatView::Stories, "3 STORIES"),
        (ThreatView::Scope, "4 SCOPE"),
        (ThreatView::Summary, "5 SUMMARY"),
    ];
    let mut spans = Vec::new();
    for (index, (view, label)) in items.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("  ", theme::subtle()));
        }
        let style = if *view == active {
            theme::selection()
        } else {
            theme::muted()
        };
        spans.push(Span::styled(*label, style));
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

pub(crate) fn stride_rollup_rows() -> Vec<(&'static str, Severity, &'static str, usize, String)> {
    vec![
        (
            "S",
            Severity::High,
            "Spoofing",
            2,
            "jwt without aud-claim, mailgun cname dangling".to_string(),
        ),
        (
            "T",
            Severity::Medium,
            "Tampering",
            1,
            "worker pool reads unsigned amqp messages".to_string(),
        ),
        ("R", Severity::Low, "Repudiation", 0, String::new()),
        (
            "I",
            Severity::Critical,
            "Info-disclosure",
            3,
            "plaintext PII at db→s3 boundary, debug logs".to_string(),
        ),
        (
            "D",
            Severity::Medium,
            "DoS",
            1,
            "no rate-limit on /checkout/confirm".to_string(),
        ),
        (
            "E",
            Severity::High,
            "Elev-of-priv",
            1,
            "admin subdomain shares jwt secret with api".to_string(),
        ),
    ]
}
