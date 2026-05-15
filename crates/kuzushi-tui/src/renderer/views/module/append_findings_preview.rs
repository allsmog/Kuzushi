use super::*;
use crate::ui_view_models::FindingsModel;

pub(in crate::renderer::views) fn append_findings_preview(
    lines: &mut Vec<Line<'static>>,
    model: &FindingsModel,
    area: Rect,
) {
    if model.rows.is_empty() {
        return;
    }

    lines.push(blank());
    let header = format!(
        "FINDINGS · {} triaged · {} pending",
        model.triaged, model.pending
    );
    lines.push(section_header_line(&header, area.width));
    for finding in model.rows.iter().take(8) {
        lines.push(compact_finding_row(
            &finding.alias,
            finding.severity,
            &finding.title,
            &finding.location,
            area.width,
        ));
    }
    append_more_findings_hint(lines, model.total);
}

pub(in crate::renderer::views) fn append_more_findings_hint(
    lines: &mut Vec<Line<'static>>,
    findings_len: usize,
) {
    if findings_len <= 8 {
        return;
    }

    lines.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(format!("… {} more · ", findings_len - 8), theme::muted()),
        Span::styled("/findings", theme::accent()),
        Span::styled(" to drill in", theme::muted()),
    ]));
}

pub(crate) fn streaming_cursor_line() -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            " ",
            Style::default().fg(theme::TERM_BG).bg(theme::T_PRIMARY),
        ),
    ])
}
