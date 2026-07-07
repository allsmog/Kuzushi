use super::*;

pub(crate) fn runs_row(
    run_id: &str,
    status: &str,
    status_style: Style,
    findings: &str,
    revision: &str,
    target: &str,
    widths: &[usize; 5],
) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}  ", pad(run_id, widths[0])), theme::accent()),
        Span::styled(
            format!("{}  ", pad(&fit(status, widths[1]), widths[1])),
            status_style,
        ),
        Span::styled(format!("{}  ", pad(findings, widths[2])), theme::primary()),
        Span::styled(
            format!("{}  ", pad(&fit(revision, widths[3]), widths[3])),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(&fit(target, widths[4]), widths[4])),
            theme::muted(),
        ),
    ])
}
