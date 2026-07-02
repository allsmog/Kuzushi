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
        proof_rank(a.1)
            .cmp(&proof_rank(b.1))
            .then_with(|| confidence_rank(a.1).cmp(&confidence_rank(b.1)))
            .then_with(|| a.1.fingerprint.cmp(&b.1.fingerprint))
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

fn proof_rank(finding: &Finding) -> u8 {
    if finding
        .verification
        .as_ref()
        .is_some_and(|verification| verification.proof_verdict == PersistedProofVerdict::Exploited)
    {
        return 0;
    }
    if finding
        .triage
        .as_ref()
        .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
    {
        return 1;
    }
    match finding.static_proof_state {
        Some(StaticProofState::StaticallyConfirmed)
        | Some(StaticProofState::SourceSinkLinked)
        | Some(StaticProofState::SanitizerChecked)
        | Some(StaticProofState::CodeCited) => 2,
        Some(StaticProofState::StaticallyRejected) => 5,
        _ => 4,
    }
}

fn confidence_rank(finding: &Finding) -> u16 {
    let confidence = finding
        .triage
        .as_ref()
        .map(|triage| triage.confidence)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    10_000u16.saturating_sub((confidence * 10_000.0).round() as u16)
}

pub(in crate::findings) fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}
