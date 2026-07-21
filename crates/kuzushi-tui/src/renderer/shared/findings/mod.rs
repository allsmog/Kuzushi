pub(in crate::renderer) use super::*;
pub(crate) use crate::ui_view_models::{SeverityCounts, SeverityTone};

/// Title owns the row. It claims the width it needs (leaving a minimum
/// location tail) and the location gets the remainder, truncated from the
/// LEFT so `…/file.rs:42` survives — a deep path must never squeeze the
/// text that says what the finding IS down to a stub.
const COMPACT_ROW_MIN_TITLE_WIDTH: usize = 12;
const COMPACT_ROW_MIN_LOCATION_WIDTH: usize = 12;

pub(crate) fn compact_finding_row(
    alias: &str,
    severity_label: &str,
    severity_tone: SeverityTone,
    name: &str,
    location: &str,
    width: u16,
) -> Line<'static> {
    let alias_w = 8;
    let sev_w = 9;
    let used = 1 + alias_w + 2 + sev_w;
    let total = (width as usize).saturating_sub(used);
    let name_w = display_width(name)
        .min(total.saturating_sub(COMPACT_ROW_MIN_LOCATION_WIDTH + 2))
        .max(COMPACT_ROW_MIN_TITLE_WIDTH.min(total));
    let location_w = total.saturating_sub(name_w + 2);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(pad(alias, alias_w), theme::accent()),
        Span::raw("  "),
        Span::styled(
            pad(severity_label, sev_w),
            theme::severity_tone(severity_tone),
        ),
        Span::styled(pad(&fit(name, name_w), name_w), theme::primary()),
        Span::styled("  ", Style::default()),
        Span::styled(fit_path(location, location_w), theme::muted()),
    ])
}
