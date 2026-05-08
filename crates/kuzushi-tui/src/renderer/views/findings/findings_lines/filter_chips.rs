use super::*;

pub(super) fn filter_chip_line(app: &ShellApp) -> Line<'static> {
    let counts = SeverityCounts::from_findings(&app.findings);
    let total = app.findings.len();
    let mut chip_spans: Vec<Span<'static>> = Vec::new();
    chip_spans.push(Span::styled("filters ", theme::label()));
    chip_spans.push(Span::styled(format!("[all:{total}]"), theme::accent()));
    for (label, n, style) in [
        (
            "critical",
            counts.critical,
            theme::severity(Severity::Critical),
        ),
        ("high", counts.high, theme::severity(Severity::High)),
        ("medium", counts.medium, theme::severity(Severity::Medium)),
        ("low", counts.low, theme::severity(Severity::Low)),
    ] {
        chip_spans.push(Span::raw("  "));
        chip_spans.push(Span::styled(format!("{label}:{n}"), style));
    }
    Line::from(chip_spans)
}
