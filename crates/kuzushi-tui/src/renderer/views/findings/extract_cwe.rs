use super::*;

pub(crate) fn extract_cwe(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    for (index, _) in upper.match_indices("CWE") {
        let mut rest = upper[index + 3..].chars();
        while matches!(rest.clone().next(), Some('-' | '_' | ' ' | ':')) {
            rest.next();
        }
        let digits = rest
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        if !digits.is_empty() {
            return Some(format!("CWE-{digits}"));
        }
    }
    None
}

pub(crate) fn finding_source_label(finding: &Finding) -> String {
    if finding.rule_id.is_empty() || finding.rule_id.starts_with(&finding.tool) {
        finding.tool.clone()
    } else {
        format!("{}:{}", finding.tool, finding.rule_id)
    }
}

pub(crate) fn finding_evidence_preview(finding: &Finding) -> String {
    let lines = finding
        .message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if let Some(evidence) = lines.iter().find_map(|line| {
        line.strip_prefix("Evidence:")
            .or_else(|| line.strip_prefix("evidence:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }) {
        return evidence.to_string();
    }

    lines
        .iter()
        .copied()
        .find(|line| *line != finding.title)
        .unwrap_or_else(|| lines.first().copied().unwrap_or(&finding.title))
        .to_string()
}
