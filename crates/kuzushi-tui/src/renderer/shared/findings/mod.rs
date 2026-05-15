pub(in crate::renderer) use super::*;

pub(crate) fn compact_finding_row(
    alias: &str,
    severity: Severity,
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
            pad(&severity.as_str().to_uppercase(), sev_w),
            theme::severity(severity),
        ),
        Span::styled(pad(&fit(name, name_w), name_w), theme::primary()),
        Span::styled("  ", Style::default()),
        Span::styled(fit(location, location_w), theme::muted()),
    ])
}

pub(crate) fn findings_count_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    if counts.critical > 0 {
        return format!("{} findings ({} critical)", findings.len(), counts.critical);
    }
    if counts.high > 0 {
        return format!("{} findings ({} high)", findings.len(), counts.high);
    }
    if counts.medium > 0 {
        return format!("{} findings ({} medium)", findings.len(), counts.medium);
    }
    format!("{} findings", findings.len())
}

#[derive(Debug, Default)]
pub(crate) struct SeverityCounts {
    pub(crate) critical: usize,
    pub(crate) high: usize,
    pub(crate) medium: usize,
    pub(crate) low: usize,
    pub(crate) info: usize,
}

impl SeverityCounts {
    pub(crate) fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
                Severity::Unknown => {}
            }
        }
        counts
    }
}
