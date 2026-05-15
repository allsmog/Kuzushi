use super::*;
use crate::ui_view_models::FindingsModel;

pub(in crate::renderer::views) fn append_findings_preview(
    lines: &mut Vec<Line<'static>>,
    model: &FindingsModel,
    area: Rect,
) {
    let preview = &model.preview;
    if preview.rows.is_empty() {
        return;
    }

    lines.push(blank());
    lines.push(section_header_line(&preview.header, area.width));
    for finding in &preview.rows {
        lines.push(compact_finding_row(
            &finding.alias,
            finding.severity,
            &finding.title,
            &finding.location,
            area.width,
        ));
    }
    if let Some(overflow) = &preview.overflow {
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled(overflow.label.clone(), theme::muted()),
            Span::styled(overflow.command, theme::accent()),
            Span::styled(overflow.suffix, theme::muted()),
        ]));
    }
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
