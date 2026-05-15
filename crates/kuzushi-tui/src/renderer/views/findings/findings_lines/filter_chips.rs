use super::*;
use crate::ui_view_models::{FindingsModel, SeverityTone};

pub(super) fn filter_chip_line(model: &FindingsModel) -> Line<'static> {
    let counts = model.counts;
    let total = model.total;
    let mut chip_spans: Vec<Span<'static>> = Vec::new();
    chip_spans.push(Span::styled("filters ", theme::label()));
    chip_spans.push(Span::styled(format!("[all:{total}]"), theme::accent()));
    for (label, n, style) in [
        (
            "critical",
            counts.critical,
            theme::severity_tone(SeverityTone::Critical),
        ),
        (
            "high",
            counts.high,
            theme::severity_tone(SeverityTone::High),
        ),
        (
            "medium",
            counts.medium,
            theme::severity_tone(SeverityTone::Medium),
        ),
        ("low", counts.low, theme::severity_tone(SeverityTone::Low)),
    ] {
        chip_spans.push(Span::raw("  "));
        chip_spans.push(Span::styled(format!("{label}:{n}"), style));
    }
    Line::from(chip_spans)
}
