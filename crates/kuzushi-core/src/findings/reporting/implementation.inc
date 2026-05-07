use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use super::{Finding, Severity, TriageVerdict, VulnSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingVerdictFilter {
    TruePositive,
    FalsePositive,
    NeedsReview,
    ByDesign,
}

impl FindingVerdictFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "tp" | "true_positive" | "vulnerable" => Ok(Self::TruePositive),
            "fp" | "false_positive" | "safe" => Ok(Self::FalsePositive),
            "needs_review" | "review" | "detected" => Ok(Self::NeedsReview),
            "by_design" | "by-design" => Ok(Self::ByDesign),
            other => anyhow::bail!("unknown findings:list verdict filter {other:?}"),
        }
    }

    fn from_finding(finding: &Finding) -> Self {
        match finding.triage.as_ref().map(|triage| triage.verdict) {
            Some(TriageVerdict::TruePositive) => Self::TruePositive,
            Some(TriageVerdict::FalsePositive) => Self::FalsePositive,
            Some(TriageVerdict::NeedsReview) | None => Self::NeedsReview,
            Some(TriageVerdict::ByDesign) => Self::ByDesign,
        }
    }

    fn as_legacy_str(self) -> &'static str {
        match self {
            Self::TruePositive => "tp",
            Self::FalsePositive => "fp",
            Self::NeedsReview => "needs_review",
            Self::ByDesign => "by_design",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingListFilter {
    pub severity: Vec<Severity>,
    pub verdict: Vec<FindingVerdictFilter>,
    pub name: Option<String>,
    pub file_path: Option<String>,
    /// Filter by discovery channel(s). Empty = no filter.
    pub vuln_source: Vec<VulnSource>,
    pub limit: usize,
}

impl Default for FindingListFilter {
    fn default() -> Self {
        Self {
            severity: Vec::new(),
            verdict: Vec::new(),
            name: None,
            file_path: None,
            vuln_source: Vec::new(),
            limit: 50,
        }
    }
}

impl FindingListFilter {
    pub const MAX_LIMIT: usize = 500;

    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(Self::MAX_LIMIT),
            ..Self::default()
        }
    }

    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut filter = Self::default();

        filter.severity = string_values(input, "severity")?
            .into_iter()
            .map(|value| Severity::try_from(value.as_str()))
            .collect::<Result<Vec<_>>>()?;
        filter.verdict = string_values(input, "verdict")?
            .into_iter()
            .map(|value| FindingVerdictFilter::from_input(&value))
            .collect::<Result<Vec<_>>>()?;
        filter.name = normalized_optional_string(input, "name")?;
        filter.file_path = normalized_optional_string(input, "filePath")?
            .or(normalized_optional_string(input, "file_path")?);
        filter.limit = match input.get("limit") {
            Some(Value::Number(number)) => number
                .as_u64()
                .with_context(|| "findings:list limit must be a non-negative integer")?
                .min(Self::MAX_LIMIT as u64) as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .with_context(|| "findings:list limit must be a non-negative integer")?
                .min(Self::MAX_LIMIT),
            Some(_) => anyhow::bail!("findings:list limit must be a number"),
            None => filter.limit,
        };

        Ok(filter)
    }

    pub fn from_parts(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        limit: usize,
    ) -> Result<Self> {
        Self::from_parts_full(severity, verdict, name, file_path, Vec::new(), limit)
    }

    pub fn from_parts_full(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        vuln_source: Vec<String>,
        limit: usize,
    ) -> Result<Self> {
        let severity = severity
            .into_iter()
            .flat_map(split_csv)
            .map(|value| Severity::try_from(value.as_str()))
            .collect::<Result<Vec<_>>>()?;
        let verdict = verdict
            .into_iter()
            .flat_map(split_csv)
            .map(|value| FindingVerdictFilter::from_input(&value))
            .collect::<Result<Vec<_>>>()?;
        let vuln_source = vuln_source
            .into_iter()
            .flat_map(split_csv)
            .map(|value| {
                VulnSource::parse(&value)
                    .ok_or_else(|| anyhow::anyhow!("unknown vuln source {value:?}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            severity,
            verdict,
            name: normalize_string(name),
            file_path: normalize_string(file_path),
            vuln_source,
            limit: limit.min(Self::MAX_LIMIT),
        })
    }

    pub(super) fn matches(&self, finding: &Finding) -> bool {
        if !self.severity.is_empty() && !self.severity.contains(&finding.severity) {
            return false;
        }

        if !self.verdict.is_empty()
            && !self
                .verdict
                .contains(&FindingVerdictFilter::from_finding(finding))
        {
            return false;
        }

        if let Some(name) = &self.name {
            let title = finding.title.to_ascii_lowercase();
            if !title.contains(name) {
                return false;
            }
        }

        if !self.vuln_source.is_empty() {
            let observed = finding
                .vuln_source
                .unwrap_or_else(|| VulnSource::from_tool(&finding.tool));
            if !self.vuln_source.contains(&observed) {
                return false;
            }
        }

        if let Some(file_path) = &self.file_path {
            let path = finding.file_path.to_ascii_lowercase();
            if !path.contains(file_path) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FindingListReport {
    pub count: usize,
    pub findings: Vec<Finding>,
}

impl FindingListReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return "  (no findings match)".to_string();
        }

        let aliased = sorted_finding_aliases(&self.findings);
        let alias_width = aliased
            .iter()
            .map(|(alias, _)| alias.len())
            .max()
            .unwrap_or(5)
            .max(5);
        let fingerprint_width = aliased
            .iter()
            .map(|(_, finding)| short_id(&finding.fingerprint).len())
            .max()
            .unwrap_or(8)
            .max(8);
        let severity_width = self
            .findings
            .iter()
            .map(|finding| finding.severity.as_str().len())
            .max()
            .unwrap_or(4)
            .max(4);
        let verdict_width = self
            .findings
            .iter()
            .map(|finding| {
                FindingVerdictFilter::from_finding(finding)
                    .as_legacy_str()
                    .len()
            })
            .max()
            .unwrap_or(5)
            .max(5);
        let name_width = self
            .findings
            .iter()
            .map(|finding| finding.title.len())
            .max()
            .unwrap_or(4)
            .max(4);

        let mut lines = vec![
            format!(
                "  {}  {}  {}  {}  {}",
                pad("Alias", alias_width),
                pad("Fingerprint", fingerprint_width),
                pad("Sev", severity_width),
                pad("Check", verdict_width),
                pad("Name", name_width)
            ),
            format!(
                "  {}  {}  {}  {}  {}",
                "-".repeat(alias_width),
                "-".repeat(fingerprint_width),
                "-".repeat(severity_width),
                "-".repeat(verdict_width),
                "-".repeat(name_width)
            ),
        ];

        for (alias, finding) in aliased {
            lines.push(format!(
                "  {}  {}  {}  {}  {}",
                pad(&alias, alias_width),
                pad(&short_id(&finding.fingerprint), fingerprint_width),
                pad(finding.severity.as_str(), severity_width),
                pad(
                    FindingVerdictFilter::from_finding(&finding).as_legacy_str(),
                    verdict_width
                ),
                finding.title
            ));
        }

        lines.push(String::new());
        lines.push(format!(
            "  {} matching (showing {})",
            self.count,
            self.findings.len()
        ));
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

pub fn format_finding_alias(index: usize) -> String {
    format!("F-{:04}", index + 1)
}

pub fn parse_finding_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("F-")
        .or_else(|| reference.strip_prefix("f-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}

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

fn string_values(input: &Value, key: &str) -> Result<Vec<String>> {
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

fn normalized_optional_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(normalize_string(Some(value.to_string()))),
        Some(_) => anyhow::bail!("findings:list {key} must be a string"),
        None => Ok(None),
    }
}

fn normalize_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn split_csv(value: String) -> impl Iterator<Item = String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .into_iter()
}

fn short_id(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Unknown => 5,
    }
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}
