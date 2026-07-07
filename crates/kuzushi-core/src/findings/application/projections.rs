use super::*;

const VERDICT_LABELS: &[(&str, &str)] = &[
    ("true_positive", "tp"),
    ("false_positive", "fp"),
    ("needs_review", "review"),
    ("by_design", "by-design"),
];

const SEVERITY_BADGES: &[(Severity, &str)] = &[
    (Severity::Critical, "🟥 CRIT"),
    (Severity::High, "🟧 HIGH"),
    (Severity::Medium, "🟨 MED"),
];

const SEVERITY_ICONS: &[(Severity, &str)] = &[
    (Severity::Critical, "🟥"),
    (Severity::High, "🟧"),
    (Severity::Medium, "🟨"),
];

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingProjection {
    pub alias: Option<String>,
    pub severity: Severity,
    pub severity_label: String,
    pub title: String,
    pub location: String,
    pub rule: String,
    pub tool: String,
    pub fingerprint: String,
    pub verdict_label: String,
    pub confidence_label: String,
    pub cwe_label: String,
    pub evidence_preview: String,
    pub proof_state: String,
    pub runtime_validation: String,
}

pub fn project_finding(finding: &Finding, alias: Option<String>) -> FindingProjection {
    FindingProjection {
        alias,
        severity: finding.severity,
        severity_label: finding.severity.as_str().to_uppercase(),
        title: finding.title.clone(),
        location: finding_location(finding),
        rule: finding.rule_id.clone(),
        tool: finding.tool.clone(),
        fingerprint: finding.fingerprint.clone(),
        verdict_label: finding_verdict_label(finding),
        confidence_label: finding_confidence_label(finding),
        cwe_label: finding_cwe_label(finding),
        evidence_preview: finding_evidence_preview(finding),
        proof_state: proof_state_label(finding.static_proof_state).to_string(),
        runtime_validation: runtime_validation_label(finding.verification.as_ref()),
    }
}

pub fn finding_location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end_line) if end_line > finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

pub fn finding_verdict_label(finding: &Finding) -> String {
    let verdict = finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
        .unwrap_or("untriaged");
    mapped_label(verdict, VERDICT_LABELS)
}

pub fn finding_confidence_label(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| format!("{:.0}%", (triage.confidence.clamp(0.0, 1.0) * 100.0)))
        .unwrap_or_else(|| "-".to_string())
}

pub fn finding_cwe_label(finding: &Finding) -> String {
    crate::findings::extract_cwe(&finding.rule_id, &finding.title, &finding.message)
        .unwrap_or_else(|| "-".to_string())
}

pub fn finding_source_label(finding: &Finding) -> String {
    if finding.rule_id.is_empty() || finding.rule_id.starts_with(&finding.tool) {
        finding.tool.clone()
    } else {
        format!("{}:{}", finding.tool, finding.rule_id)
    }
}

pub fn finding_evidence_preview(finding: &Finding) -> String {
    if let Some(first) = finding.evidence.first() {
        return format!(
            "evidence {} anchors · top: {} {}:{}",
            finding.evidence.len(),
            first.kind,
            first.file_path,
            first.line
        );
    }
    let lines = finding
        .message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if let Some(evidence) = evidence_line(&lines) {
        return evidence.to_string();
    }
    lines
        .iter()
        .copied()
        .find(|line| *line != finding.title)
        .unwrap_or_else(|| lines.first().copied().unwrap_or(&finding.title))
        .to_string()
}

pub fn finding_remediation_hint(finding: &Finding) -> Option<String> {
    if let Some(remediation) = finding
        .remediation
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        return Some(remediation.trim().to_string());
    }
    finding
        .message
        .lines()
        .map(str::trim)
        .find_map(remediation_line)
}

fn remediation_line(line: &str) -> Option<String> {
    let hint = line
        .strip_prefix("Remediation:")
        .or_else(|| line.strip_prefix("Fix:"))?
        .trim();
    (!hint.is_empty()).then(|| hint.to_string())
}

pub fn severity_badge(severity: Severity) -> &'static str {
    severity_label(severity, SEVERITY_BADGES, "⬜ LOW")
}

pub fn severity_icon(severity: Severity) -> &'static str {
    severity_label(severity, SEVERITY_ICONS, "⬜")
}

fn mapped_label(value: &str, labels: &[(&str, &str)]) -> String {
    labels
        .iter()
        .find_map(|(candidate, label)| (*candidate == value).then_some(*label))
        .unwrap_or(value)
        .to_string()
}

fn severity_label(
    severity: Severity,
    labels: &[(Severity, &'static str)],
    default: &'static str,
) -> &'static str {
    labels
        .iter()
        .find_map(|(candidate, label)| (*candidate == severity).then_some(*label))
        .unwrap_or(default)
}

fn evidence_line<'a>(lines: &'a [&'a str]) -> Option<&'a str> {
    lines.iter().find_map(|line| {
        line.strip_prefix("Evidence:")
            .or_else(|| line.strip_prefix("evidence:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}
