pub(in crate::renderer) use super::*;
pub(crate) use crate::ui_view_models::{findings_count_summary, SeverityCounts, SeverityTone};

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
    let location_w = location.chars().count().min(total.saturating_sub(2)).max(8);
    let name_w = total.saturating_sub(location_w + 2).max(12);
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
        Span::styled(fit(location, location_w), theme::muted()),
    ])
}
