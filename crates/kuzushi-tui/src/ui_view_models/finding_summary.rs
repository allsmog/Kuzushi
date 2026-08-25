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

/// The counts a findings segment has to reconcile. `shown` is what the view
/// projection rendered, `loaded` is what the session holds, and `total` is
/// what the ledger matched. Each step narrows for a different reason, so one
/// ratio spanning them would attribute every missing row to the last step.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FindingsNarrowing {
    pub(crate) shown: usize,
    pub(crate) loaded: usize,
    pub(crate) total: usize,
}

/// Chrome that prints a bare projection count cannot be told apart from chrome
/// that prints the ledger, and both render on the same frame — so the
/// projection names what it narrows.
pub(crate) fn status_footer_findings_summary_from_counts(
    narrowing: FindingsNarrowing,
    counts: SeverityCounts,
) -> String {
    status_footer_findings_parts(findings_narrowing_label(narrowing), counts)
}

pub(crate) fn compact_status_footer_findings_summary_from_counts(
    narrowing: FindingsNarrowing,
    counts: SeverityCounts,
) -> String {
    compact_status_footer_findings_parts(findings_narrowing_label(narrowing), counts)
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
        // A projection can only hide loaded rows, so a `loaded` below `shown`
        // is not a reachable state; report the rendered count rather than a
        // negative remainder.
        assert_eq!(shown_findings_label(4, 2), "4 findings".to_string());
    }

    #[test]
    fn a_narrowed_projection_summary_keeps_its_severity_mix() {
        let counts = SeverityCounts {
            high: 25,
            medium: 2,
            ..SeverityCounts::default()
        };
        let narrowing = FindingsNarrowing {
            shown: 27,
            loaded: 31,
            total: 31,
        };

        assert_eq!(
            status_footer_findings_summary_from_counts(narrowing, counts),
            "27/31 findings shown / 25 high / 2 med"
        );
        assert_eq!(
            compact_status_footer_findings_summary_from_counts(narrowing, counts),
            "27/31 findings shown · 25 H · 2 M"
        );
    }

    /// `FindingListFilter::MAX_LIMIT` caps a reload at 500 rows while the
    /// report still counts every match, so a big ledger narrows twice. Blaming
    /// the projection for the rows the limit dropped would restate the bug
    /// this label exists to fix.
    #[test]
    fn a_doubly_narrowed_count_separates_hidden_rows_from_unloaded_ones() {
        assert_eq!(
            findings_narrowing_label(FindingsNarrowing {
                shown: 450,
                loaded: 500,
                total: 700,
            }),
            "450/500 findings shown of 700 matched"
        );
    }

    #[test]
    fn each_narrowing_alone_reads_as_itself() {
        // Loaded everything, projection hid some.
        assert_eq!(
            findings_narrowing_label(FindingsNarrowing {
                shown: 27,
                loaded: 31,
                total: 31,
            }),
            "27/31 findings shown"
        );
        // Projection hid nothing, the limit dropped rows — the rail renders
        // this same phrase from the ledger, so the two must agree verbatim.
        assert_eq!(
            findings_narrowing_label(FindingsNarrowing {
                shown: 500,
                loaded: 500,
                total: 700,
            }),
            "500/700 findings loaded"
        );
        // Neither narrowed.
        assert_eq!(
            findings_narrowing_label(FindingsNarrowing {
                shown: 4,
                loaded: 4,
                total: 4,
            }),
            "4 findings"
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

/// `shown` came off a view projection, which can only hide rows the session
/// already loaded — so it is measured against `loaded`, never the ledger.
fn shown_findings_label(shown: usize, loaded: usize) -> String {
    narrowed_findings_label(shown, loaded, "shown")
}

/// A projection hides loaded rows; a list limit leaves rows unloaded. A frame
/// that hit both has to name both, because the single ratio `shown/total`
/// would report rows that were never loaded as rows the projection hid.
fn findings_narrowing_label(narrowing: FindingsNarrowing) -> String {
    let FindingsNarrowing {
        shown,
        loaded,
        total,
    } = narrowing;
    if shown < loaded && loaded < total {
        return format!("{shown}/{loaded} findings shown of {total} matched");
    }
    if shown < loaded {
        return shown_findings_label(shown, loaded);
    }
    loaded_findings_label(loaded, total)
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
