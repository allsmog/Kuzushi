use kuzushi_core::{Finding, Severity};

pub(crate) fn findings_count_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    let total = findings.len();
    if counts.critical > 0 {
        return format!(
            "{total} {} ({} critical)",
            finding_noun(total),
            counts.critical
        );
    }
    if counts.high > 0 {
        return format!("{total} {} ({} high)", finding_noun(total), counts.high);
    }
    if counts.medium > 0 {
        return format!("{total} {} ({} medium)", finding_noun(total), counts.medium);
    }
    format!("{total} {}", finding_noun(total))
}

pub(crate) fn status_footer_findings_summary(findings: &[Finding]) -> String {
    let counts = SeverityCounts::from_findings(findings);
    let total = findings.len();
    let mut parts = vec![format!("{total} {}", finding_noun(total))];
    append_nonzero_severity(&mut parts, counts.critical, "critical");
    append_nonzero_severity(&mut parts, counts.high, "high");
    append_nonzero_severity(&mut parts, counts.medium, "medium");
    parts.join(" / ")
}

pub(crate) fn ci_result_findings_summary(findings: &[Finding], fallback_count: usize) -> String {
    if findings.is_empty() && fallback_count > 0 {
        return format!("{fallback_count} {}", finding_noun(fallback_count));
    }
    status_footer_findings_summary(findings)
}

fn finding_noun(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}

fn append_nonzero_severity(parts: &mut Vec<String>, count: usize, label: &str) {
    if count > 0 {
        parts.push(format!("{count} {label}"));
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
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
            counts.add(finding.severity);
        }
        counts
    }

    fn add(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
            Severity::Unknown => {}
        }
    }
}
