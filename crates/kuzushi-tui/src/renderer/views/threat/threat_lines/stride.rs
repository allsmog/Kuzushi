use super::*;
use crate::ui_view_models::{SeverityTone, ThreatStrideMember, ThreatStrideRow, ThreatStrideTone};

pub(super) fn append_stride_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let rollup = crate::ui_view_models::threat_stride_rollup(app);
    lines.push(section_header_line(&rollup.header, area.width));
    if let Some(hint) = &rollup.empty_hint {
        lines.push(empty_hint_line(hint));
        return;
    }
    for row in &rollup.rows {
        lines.push(stride_row(row, area.width));
        for member in &row.members {
            lines.push(stride_member_row(member, area.width));
        }
    }
}

/// One indented row per threat in the category: id · severity · title. The
/// rollup fills its space with the real threats instead of blank rows.
fn stride_member_row(member: &ThreatStrideMember, width: u16) -> Line<'static> {
    let title_w = (width as usize).saturating_sub(8 + 6 + 10 + 4).max(8);
    Line::from(vec![
        Span::raw("        "),
        Span::styled(pad(&member.id, 6), theme::primary()),
        Span::styled(
            pad(&member.severity, 10),
            threat_stride_tone_style(member.tone),
        ),
        Span::styled(fit(&member.title, title_w), theme::muted()),
    ])
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
        ThreatStrideTone::Critical => theme::severity_tone(SeverityTone::Critical),
        ThreatStrideTone::High => theme::severity_tone(SeverityTone::High),
        ThreatStrideTone::Medium => theme::severity_tone(SeverityTone::Medium),
        ThreatStrideTone::Low => theme::severity_tone(SeverityTone::Low),
        ThreatStrideTone::Info => theme::severity_tone(SeverityTone::Info),
        ThreatStrideTone::Unknown => theme::severity_tone(SeverityTone::Unknown),
    }
}
