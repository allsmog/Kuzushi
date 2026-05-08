use super::prelude::*;
use super::*;

pub fn sorted_finding_aliases(findings: &[Finding]) -> Vec<(String, Finding)> {
    let mut indexed: Vec<&Finding> = findings.iter().collect();
    indexed.sort_by(|a, b| {
        let by_severity = severity_rank(a.severity).cmp(&severity_rank(b.severity));
        if by_severity == std::cmp::Ordering::Equal {
            a.fingerprint.cmp(&b.fingerprint)
        } else {
            by_severity
        }
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(index, finding)| (format_finding_alias(index), finding.clone()))
        .collect()
}

pub fn stable_finding_alias(findings: &[Finding], fingerprint: &str) -> Option<String> {
    sorted_finding_aliases(findings)
        .into_iter()
        .find(|(_, finding)| finding.fingerprint == fingerprint)
        .map(|(alias, _)| alias)
}

pub fn resolve_finding_alias(findings: &[Finding], reference: &str) -> Option<Finding> {
    let index = parse_finding_alias(reference)?;
    sorted_finding_aliases(findings)
        .into_iter()
        .nth(index)
        .map(|(_, finding)| finding)
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

pub(in crate::findings) fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}
