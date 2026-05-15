use super::*;
use crate::ui_view_models::{ThreatStrideRow, ThreatStrideTone};

pub(super) fn append_stride_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let rollup = crate::ui_view_models::threat_stride_rollup(app);
    lines.push(section_header_line(&rollup.header, area.width));
    for row in &rollup.rows {
        lines.push(stride_row(row, area.width));
    }
}

fn stride_row(row: &ThreatStrideRow, width: u16) -> Line<'static> {
    let total = width as usize;
    let used = 3 + 3 + 1 + 16 + 4 + 10;
    let desc_w = total.saturating_sub(used).max(8);
    let [letter, category, count, issue_label] = &row.cells;
    let mut spans = vec![
        Span::raw("   "),
        Span::styled(format!(" {letter} "), threat_stride_tone_style(row.tone)),
        Span::raw(" "),
        Span::styled(pad(category, 16), theme::muted()),
        Span::styled(format!("{count} "), theme::primary()),
        Span::styled(issue_label.clone(), theme::muted()),
    ];
    if let Some(detail) = &row.detail {
        spans.push(Span::styled("  · ", theme::muted()));
        spans.push(Span::styled(fit(detail, desc_w), theme::muted()));
    }
    Line::from(spans)
}

fn threat_stride_tone_style(tone: ThreatStrideTone) -> Style {
    match tone {
        ThreatStrideTone::Critical => theme::severity(Severity::Critical),
        ThreatStrideTone::High => theme::severity(Severity::High),
        ThreatStrideTone::Medium => theme::severity(Severity::Medium),
        ThreatStrideTone::Low => theme::severity(Severity::Low),
        ThreatStrideTone::Info => theme::severity(Severity::Info),
        ThreatStrideTone::Unknown => theme::severity(Severity::Unknown),
    }
}
