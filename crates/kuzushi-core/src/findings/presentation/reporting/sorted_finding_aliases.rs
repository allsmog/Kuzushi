use super::*;

pub fn sorted_finding_aliases(findings: &[Finding]) -> Vec<(String, Finding)> {
    sorted_finding_alias_indices(findings)
        .into_iter()
        .map(|(alias, index)| (alias, findings[index].clone()))
        .collect()
}

pub fn sorted_finding_alias_indices(findings: &[Finding]) -> Vec<(String, usize)> {
    let mut indexed: Vec<(usize, &Finding)> = findings.iter().enumerate().collect();
    indexed.sort_by(|a, b| {
        let by_severity = severity_rank(a.1.severity).cmp(&severity_rank(b.1.severity));
        if by_severity != std::cmp::Ordering::Equal {
            return by_severity;
        }
        a.1.fingerprint.cmp(&b.1.fingerprint)
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(alias_index, (finding_index, _))| (format_finding_alias(alias_index), finding_index))
        .collect()
}

pub fn stable_finding_alias(findings: &[Finding], fingerprint: &str) -> Option<String> {
    sorted_finding_alias_indices(findings)
        .into_iter()
        .find(|(_, index)| findings[*index].fingerprint == fingerprint)
        .map(|(alias, _)| alias)
}

pub fn resolve_finding_alias(findings: &[Finding], reference: &str) -> Option<Finding> {
    let index = parse_finding_alias(reference)?;
    sorted_finding_alias_indices(findings)
        .into_iter()
        .nth(index)
        .and_then(|(_, finding_index)| findings.get(finding_index).cloned())
}

pub(in crate::findings) fn string_values(input: &Value, key: &str) -> Result<Vec<String>> {
    let Some(value) = input.get(key) else {
        return Ok(Vec::new());
    };

    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| match value {
                Value::String(text) => Ok(split_csv(text.to_string())),
                other => {
                    anyhow::bail!("findings:list {key} entries must be strings, got {}", other)
                }
            })
            .collect::<Result<Vec<_>>>()
            .map(|values| values.into_iter().flatten().collect()),
        Value::String(text) => Ok(split_csv(text.to_string()).collect()),
        _ => anyhow::bail!("findings:list {key} must be an array of strings"),
    }
}

pub(in crate::findings) fn normalized_optional_string(
    input: &Value,
    key: &str,
) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(normalize_string(Some(value.to_string()))),
        Some(_) => anyhow::bail!("findings:list {key} must be a string"),
        None => Ok(None),
    }
}

pub(in crate::findings) fn normalize_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

pub(in crate::findings) fn split_csv(value: String) -> impl Iterator<Item = String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .into_iter()
}

pub(in crate::findings) fn short_id(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}

/// The axis used to order findings for *display*. Alias identity (`F-0001…`) is
/// always assigned severity-major by `sorted_finding_alias_indices` and is never
/// affected by this — only the presentation order changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSortAxis {
    /// Confidence first (`Confirmed` before `Unverified`), then severity. Puts a
    /// confirmed-exploitable finding above a CVSS-high-but-unverified one.
    ConfidenceThenSeverity,
    /// Severity first, then confidence. The historical order.
    SeverityThenConfidence,
}

/// Total order over findings by `(confidence, severity, fingerprint)`. Shared by
/// the core display sort and the Workbench display funnel so both agree.
pub fn compare_findings_by_confidence(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    ProofConfidence::classify(a)
        .rank()
        .cmp(&ProofConfidence::classify(b).rank())
        .then_with(|| severity_rank(a.severity).cmp(&severity_rank(b.severity)))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

fn compare_findings_by_severity(a: &Finding, b: &Finding) -> std::cmp::Ordering {
    severity_rank(a.severity)
        .cmp(&severity_rank(b.severity))
        .then_with(|| ProofConfidence::classify(a).rank().cmp(&ProofConfidence::classify(b).rank()))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

/// Findings paired with their stable severity-major aliases, re-ordered for
/// display along `axis`. Alias strings stay attached to their findings, so
/// `F-0001` identity is unchanged — only row order moves.
pub fn sorted_finding_display_indices(
    findings: &[Finding],
    axis: FindingSortAxis,
) -> Vec<(String, usize)> {
    let mut aliased = sorted_finding_alias_indices(findings);
    aliased.sort_by(|a, b| match axis {
        FindingSortAxis::ConfidenceThenSeverity => {
            compare_findings_by_confidence(&findings[a.1], &findings[b.1])
        }
        FindingSortAxis::SeverityThenConfidence => {
            compare_findings_by_severity(&findings[a.1], &findings[b.1])
        }
    });
    aliased
}

pub(in crate::findings) fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Unknown => 5,
    }
}

pub(in crate::findings) fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

#[cfg(test)]
mod display_sort_tests {
    use super::*;
    use crate::findings::domain::{PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification};

    fn finding(fingerprint: &str, severity: Severity, verification: Option<PersistedVerification>) -> Finding {
        Finding {
            fingerprint: fingerprint.to_string(),
            severity,
            verification,
            ..Finding::default()
        }
    }

    fn confirmed() -> PersistedVerification {
        PersistedVerification {
            proof_level: 3,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Plain,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: Vec::new(),
            created_at: String::new(),
        }
    }

    #[test]
    fn confidence_first_puts_low_confirmed_above_critical_unverified() {
        let findings = vec![
            finding("crit", Severity::Critical, None),
            finding("low", Severity::Low, Some(confirmed())),
        ];
        let order = sorted_finding_display_indices(&findings, FindingSortAxis::ConfidenceThenSeverity);
        // The confirmed low finding sorts to the top under confidence-first.
        assert_eq!(findings[order[0].1].fingerprint, "low");
        assert_eq!(findings[order[1].1].fingerprint, "crit");
    }

    #[test]
    fn severity_first_keeps_critical_on_top() {
        let findings = vec![
            finding("crit", Severity::Critical, None),
            finding("low", Severity::Low, Some(confirmed())),
        ];
        let order = sorted_finding_display_indices(&findings, FindingSortAxis::SeverityThenConfidence);
        assert_eq!(findings[order[0].1].fingerprint, "crit");
        assert_eq!(findings[order[1].1].fingerprint, "low");
    }

    #[test]
    fn aliases_stay_severity_major_regardless_of_display_axis() {
        let findings = vec![
            finding("crit", Severity::Critical, None),
            finding("low", Severity::Low, Some(confirmed())),
        ];
        let display =
            sorted_finding_display_indices(&findings, FindingSortAxis::ConfidenceThenSeverity);
        // `crit` (index 0) keeps alias F-0001 even though it displays second.
        let crit_alias = display
            .iter()
            .find(|(_, index)| findings[*index].fingerprint == "crit")
            .map(|(alias, _)| alias.clone());
        assert_eq!(crit_alias.as_deref(), Some("F-0001"));
    }
}
