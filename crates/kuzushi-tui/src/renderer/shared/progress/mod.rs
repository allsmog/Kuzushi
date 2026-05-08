pub(in crate::renderer) use super::*;

pub(crate) fn pipeline_row(symbol: &str, label: &str, detail: &str) -> Line<'static> {
    let style = match symbol {
        "✓" => theme::success(),
        "→" | "⏵" => theme::accent(),
        _ => theme::subtle(),
    };
    Line::from(vec![
        Span::styled(format!("{symbol} "), style),
        Span::styled(pad(label, 24), theme::label()),
        Span::styled(detail.to_string(), theme::muted()),
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgressKind {
    Done,
    Active,
    Queued,
    /// Reserved for genuine error states (e.g. scan task crashed,
    /// preflight check failed).  No call site currently produces it
    /// because every "task didn't run" path correctly uses `Queued`,
    /// but keeping the variant + danger-red style makes the API
    /// honest if/when we need it.
    #[allow(dead_code)]
    Failing,
}

impl ProgressKind {
    fn fill_style(self) -> Style {
        match self {
            ProgressKind::Done => theme::success(),
            ProgressKind::Active => theme::warn(),
            // Queued bars stay subtle in the mockup
            // (`design/mockups/sast-running.jsx::bar` passes c-subtle for
            // the "queued" status); `Failing` should be reserved for true
            // errors so a deferred task isn't painted danger-red.
            ProgressKind::Queued => theme::subtle(),
            ProgressKind::Failing => theme::danger(),
        }
    }

    fn status_style(self) -> Style {
        match self {
            ProgressKind::Done => theme::success(),
            ProgressKind::Active => theme::warn(),
            // Pre-flight queued status reads better in muted than subtle —
            // `c-subtle` empty cells need a slightly stronger label.
            ProgressKind::Queued => theme::muted(),
            ProgressKind::Failing => theme::danger(),
        }
    }
}

/// Render a progress bar matching `design/mockups/sast.jsx::bar()`:
///
/// ```text
///    semgrep              [████████████████████░░░░]  612/612   done · 18 raw hits
/// ```
pub(crate) fn progress_bar_line(
    label: &str,
    done: usize,
    total: usize,
    status: &str,
    kind: ProgressKind,
) -> Line<'static> {
    let bar_width: usize = 24;
    let filled = if total == 0 {
        0
    } else {
        let raw = (bar_width as f64 * done as f64 / total as f64).round() as usize;
        raw.min(bar_width)
    };
    let empty = bar_width - filled;
    let count = format!("{done}/{total}");
    let count = format!("{:>7}", count);

    Line::from(vec![
        Span::raw("   "),
        Span::styled(pad(label, 20), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(filled), kind.fill_style()),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(count, theme::muted()),
        Span::raw("  "),
        Span::styled(status.to_string(), kind.status_style()),
    ])
}
