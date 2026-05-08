use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PatchDiffSummary {
    pub(crate) files: usize,
    pub(crate) adds: usize,
    pub(crate) dels: usize,
}

pub(crate) fn patch_diff_summary(diff: &str) -> PatchDiffSummary {
    let mut summary = PatchDiffSummary::default();
    for line in diff.lines() {
        if line.starts_with("+++") {
            summary.files += 1;
        } else if line.starts_with('+') && !line.starts_with("+++") {
            summary.adds += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            summary.dels += 1;
        }
    }
    if summary.files == 0 && (summary.adds > 0 || summary.dels > 0) {
        summary.files = 1;
    }
    summary
}

pub(crate) fn patch_diff_lines(diff: &str, width: u16) -> Vec<Line<'static>> {
    let body_width = (width as usize).saturating_sub(7);
    let mut out = Vec::new();
    for raw in diff.lines() {
        let line = if raw.starts_with("+++") || raw.starts_with("---") {
            Line::from(vec![
                Span::raw("   "),
                Span::styled("── ", theme::subtle()),
                Span::styled(fit(raw, body_width), theme::accent()),
            ])
        } else if let Some(rest) = raw.strip_prefix("@@") {
            Line::from(vec![
                Span::raw("   "),
                Span::styled(format!("@@{rest}"), theme::subtle()),
            ])
        } else if let Some(rest) = raw.strip_prefix('+') {
            Line::from(vec![
                Span::raw("     "),
                Span::styled("+ ", theme::success()),
                Span::styled(fit(rest, body_width), theme::success()),
            ])
        } else if let Some(rest) = raw.strip_prefix('-') {
            Line::from(vec![
                Span::raw("     "),
                Span::styled("- ", theme::danger()),
                Span::styled(fit(rest, body_width), theme::danger()),
            ])
        } else {
            Line::from(vec![
                Span::raw("       "),
                Span::styled(fit(raw, body_width), theme::muted()),
            ])
        };
        out.push(line);
    }
    out
}
