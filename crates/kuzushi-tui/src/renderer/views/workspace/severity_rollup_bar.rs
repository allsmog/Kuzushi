use super::*;

pub(crate) fn severity_rollup_bar(
    label: &str,
    n: usize,
    total: usize,
    severity: Severity,
) -> Line<'static> {
    let bar_w: usize = 28;
    let filled = if total == 0 {
        0
    } else {
        ((bar_w * n) as f64 / total as f64).round() as usize
    };
    let filled = filled.clamp(if n > 0 { 1 } else { 0 }, bar_w);
    let empty = bar_w - filled;
    Line::from(vec![
        Span::raw(" "),
        Span::styled(label.to_string(), theme::severity(severity)),
        Span::styled(" [".to_string(), theme::subtle()),
        Span::styled("█".repeat(filled), theme::severity(severity)),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ".to_string(), theme::subtle()),
        Span::styled(format!("{n:>3}"), theme::primary()),
        Span::styled("/".to_string(), theme::subtle()),
        Span::styled(total.to_string(), theme::muted()),
    ])
}
