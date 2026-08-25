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

/// A view projection narrows the ledger (engagement dedupe, component scope,
/// backlog preset, search) without unloading anything, so `shown` is the only
/// number these counts describe. Callers pass the ledger `total` alongside it
/// because chrome that prints a bare projection count cannot be told apart
/// from chrome that prints the ledger — and both render on the same frame.
pub(crate) fn status_footer_findings_summary_from_counts(
    shown: usize,
    total: usize,
    counts: SeverityCounts,
) -> String {
    status_footer_findings_parts(shown_findings_label(shown, total), counts)
}

pub(crate) fn compact_status_footer_findings_summary_from_counts(
    shown: usize,
    total: usize,
    counts: SeverityCounts,
) -> String {
    compact_status_footer_findings_parts(shown_findings_label(shown, total), counts)
}

pub(crate) fn compact_status_footer_findings_summary_with_total(
    findings: &[Finding],
    total: usize,
) -> String {
    compact_status_footer_findings_summary_with_loaded(
        findings.len(),
        total,
        SeverityCounts::from_findings(findings),
    )
}

fn compact_status_footer_findings_summary_with_loaded(
    loaded: usize,
    total: usize,
    counts: SeverityCounts,
) -> String {
    compact_status_footer_findings_parts(loaded_findings_label(loaded, total), counts)
}

fn status_footer_findings_summary_from_counts_with_loaded(
    loaded: usize,
    total: usize,
    counts: SeverityCounts,
) -> String {
    status_footer_findings_parts(loaded_findings_label(loaded, total), counts)
}

fn status_footer_findings_parts(label: String, counts: SeverityCounts) -> String {
    let mut parts = vec![label];
    append_nonzero_severity(&mut parts, counts.critical, "crit");
    append_nonzero_severity(&mut parts, counts.high, "high");
    append_nonzero_severity(&mut parts, counts.medium, "med");
    parts.join(" / ")
}

fn compact_status_footer_findings_parts(label: String, counts: SeverityCounts) -> String {
    let mut parts = vec![label];
    append_nonzero_severity(&mut parts, counts.critical, "C");
    append_nonzero_severity(&mut parts, counts.high, "H");
    append_nonzero_severity(&mut parts, counts.medium, "M");
    parts.join(" · ")
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

    /// Rows past the list limit are absent from the session; rows a projection
    /// hides are present but not rendered. Both narrow, so both must say so,
    /// and the qualifier is the only thing separating the two situations.
    #[test]
    fn narrowed_labels_name_why_the_count_is_short() {
        assert_eq!(
            loaded_findings_label(27, 31),
            "27/31 findings loaded".to_string()
        );
        assert_eq!(
            shown_findings_label(27, 31),
            "27/31 findings shown".to_string()
        );
    }

    #[test]
    fn an_unnarrowed_count_reads_as_a_plain_total() {
        assert_eq!(shown_findings_label(1, 1), "1 finding".to_string());
        assert_eq!(shown_findings_label(4, 4), "4 findings".to_string());
        // A projection can only hide rows, so a `total` below `shown` is not a
        // reachable state; report the rendered count rather than a negative
        // remainder.
        assert_eq!(shown_findings_label(4, 2), "4 findings".to_string());
    }

    #[test]
    fn a_narrowed_projection_summary_keeps_its_severity_mix() {
        let counts = SeverityCounts {
            high: 25,
            medium: 2,
            ..SeverityCounts::default()
        };

        assert_eq!(
            status_footer_findings_summary_from_counts(27, 31, counts),
            "27/31 findings shown / 25 high / 2 med"
        );
        assert_eq!(
            compact_status_footer_findings_summary_from_counts(27, 31, counts),
            "27/31 findings shown · 25 H · 2 M"
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

/// `loaded` came off the store clamped by a list limit, so the rows beyond it
/// are genuinely absent from this session.
fn loaded_findings_label(loaded: usize, total: usize) -> String {
    narrowed_findings_label(loaded, total, "loaded")
}

/// `shown` came off a view projection over rows that are all loaded, so the
/// difference is hidden, not missing.
fn shown_findings_label(shown: usize, total: usize) -> String {
    narrowed_findings_label(shown, total, "shown")
}

fn narrowed_findings_label(visible: usize, total: usize, qualifier: &str) -> String {
    if total > visible {
        format!("{visible}/{total} findings {qualifier}")
    } else {
        format!("{visible} {}", finding_noun(visible))
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
