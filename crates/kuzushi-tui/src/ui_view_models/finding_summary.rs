use kuzushi_core::{Finding, Severity};

pub(crate) fn findings_count_summary_with_total(findings: &[Finding], total: usize) -> String {
    let counts = SeverityCounts::from_findings(findings);
    let loaded = findings.len();
    let base = loaded_findings_label(loaded, total);
    if counts.critical > 0 {
        return format!("{base} ({} critical)", counts.critical);
    }
    if counts.high > 0 {
        return format!("{base} ({} high)", counts.high);
    }
    if counts.medium > 0 {
        return format!("{base} ({} medium)", counts.medium);
    }
    base
}

pub(crate) fn status_footer_findings_summary(findings: &[Finding]) -> String {
    status_footer_findings_summary_with_total(findings, findings.len())
}

pub(crate) fn status_footer_findings_summary_with_total(
    findings: &[Finding],
    total: usize,
) -> String {
    let counts = SeverityCounts::from_findings(findings);
    status_footer_findings_summary_from_counts_with_loaded(findings.len(), total, counts)
}

pub(crate) fn status_footer_findings_summary_from_counts(
    total: usize,
    counts: SeverityCounts,
) -> String {
    status_footer_findings_summary_from_counts_with_loaded(total, total, counts)
}

pub(crate) fn status_footer_findings_summary_from_counts_with_loaded(
    loaded: usize,
    total: usize,
    counts: SeverityCounts,
) -> String {
    let mut parts = vec![loaded_findings_label(loaded, total)];
    append_nonzero_severity(&mut parts, counts.critical, "crit");
    append_nonzero_severity(&mut parts, counts.high, "high");
    append_nonzero_severity(&mut parts, counts.medium, "med");
    parts.join(" / ")
}

pub(crate) fn ci_result_findings_summary(findings: &[Finding], fallback_count: usize) -> String {
    if fallback_count > findings.len() {
        return format!("{fallback_count} {}", finding_noun(fallback_count));
    }
    status_footer_findings_summary(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding::new_semgrep("demo.rule", "src/app.rs", 1, None, severity, "demo")
    }

    #[test]
    fn status_footer_summary_uses_compact_severity_labels() {
        let findings = [
            finding(Severity::High),
            finding(Severity::High),
            finding(Severity::Medium),
        ];

        assert_eq!(
            status_footer_findings_summary(&findings),
            "3 findings / 2 high / 1 med"
        );
    }
}

fn finding_noun(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}

fn loaded_findings_label(loaded: usize, total: usize) -> String {
    if total > loaded {
        format!("{loaded}/{total} findings loaded")
    } else {
        format!("{loaded} {}", finding_noun(loaded))
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

    pub(crate) fn add(&mut self, severity: Severity) {
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
