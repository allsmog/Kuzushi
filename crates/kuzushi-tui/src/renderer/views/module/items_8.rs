use super::prelude::*;
use super::*;

pub(in crate::renderer::views) fn append_findings_preview(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    area: Rect,
) {
    if app.findings.is_empty() {
        return;
    }

    lines.push(blank());
    let triaged = app
        .findings
        .iter()
        .filter(|finding| finding.triage.is_some())
        .count();
    let pending = app.findings.len().saturating_sub(triaged);
    let header = format!("FINDINGS · {triaged} triaged · {pending} pending");
    lines.push(section_header_line(&header, area.width));
    for (alias, finding) in sorted_finding_aliases(&app.findings).into_iter().take(8) {
        lines.push(compact_finding_row(
            &alias,
            finding.severity,
            &finding.title,
            &finding_location(&finding),
            area.width,
        ));
    }
    append_more_findings_hint(lines, app.findings.len());
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
