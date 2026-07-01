use super::*;

const TOOL_JSON_MESSAGE_LIMIT: usize = 1_000;
const TOOL_JSON_EVIDENCE_LIMIT: usize = 3;
const TOOL_JSON_EVIDENCE_TEXT_LIMIT: usize = 300;

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

        finding_list_output_lines(self).join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        crate::module_result::completed_output_result(
            self.summary(),
            self.output(),
            json!(FindingListToolData::from_report(self)),
        )
    }

    fn summary(&self) -> String {
        format!(
            "findings:list: {} matching finding{}",
            self.count,
            plural_suffix(self.count)
        )
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingListToolData {
    count: usize,
    findings: Vec<FindingListToolFinding>,
}

impl FindingListToolData {
    fn from_report(report: &FindingListReport) -> Self {
        let aliased = sorted_finding_aliases(&report.findings);
        Self {
            count: report.count,
            findings: aliased
                .iter()
                .map(|(alias, finding)| FindingListToolFinding::from_finding(alias, finding))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct FindingListToolFinding {
    alias: String,
    fingerprint: String,
    rule_id: String,
    title: String,
    severity: String,
    file_path: String,
    start_line: u32,
    end_line: Option<u32>,
    message: String,
    tool: String,
    triage: Option<TriageOutcome>,
    verification: Option<PersistedVerification>,
    evidence: Vec<FindingListToolEvidence>,
}

impl FindingListToolFinding {
    fn from_finding(alias: &str, finding: &Finding) -> Self {
        Self {
            alias: alias.to_string(),
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            severity: finding.severity.as_str().to_string(),
            file_path: finding.file_path.clone(),
            start_line: finding.start_line,
            end_line: finding.end_line,
            message: cap_tool_json_text(&finding.message, TOOL_JSON_MESSAGE_LIMIT),
            tool: finding.tool.clone(),
            triage: finding.triage.clone(),
            verification: finding.verification.clone(),
            evidence: finding
                .evidence
                .iter()
                .take(TOOL_JSON_EVIDENCE_LIMIT)
                .map(FindingListToolEvidence::from_evidence)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingListToolEvidence {
    kind: String,
    file_path: String,
    line: u32,
    snippet: String,
    rationale: String,
    confidence: u8,
    request_blob_present: bool,
    response_blob_present: bool,
}

impl FindingListToolEvidence {
    fn from_evidence(evidence: &FindingEvidence) -> Self {
        Self {
            kind: evidence.kind.clone(),
            file_path: evidence.file_path.clone(),
            line: evidence.line,
            snippet: cap_tool_json_text(&evidence.snippet, TOOL_JSON_EVIDENCE_TEXT_LIMIT),
            rationale: cap_tool_json_text(&evidence.rationale, TOOL_JSON_EVIDENCE_TEXT_LIMIT),
            confidence: evidence.confidence,
            request_blob_present: evidence.request_blob.is_some(),
            response_blob_present: evidence.response_blob.is_some(),
        }
    }
}

fn cap_tool_json_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut capped = value.chars().take(max_chars).collect::<String>();
    capped.push_str("...");
    capped
}

#[derive(Debug, Clone, Copy)]
struct FindingTableWidths {
    alias: usize,
    fingerprint: usize,
    severity: usize,
    verdict: usize,
    name: usize,
}

fn finding_list_output_lines(report: &FindingListReport) -> Vec<String> {
    let aliased = sorted_finding_aliases(&report.findings);
    let widths = finding_table_widths(&aliased, &report.findings);
    let mut lines = finding_table_header(widths);
    lines.extend(
        aliased
            .iter()
            .map(|(alias, finding)| finding_table_row(alias, finding, widths)),
    );
    lines.push(String::new());
    lines.push(matching_line(report));
    lines
}

fn finding_table_widths(aliased: &[(String, Finding)], findings: &[Finding]) -> FindingTableWidths {
    FindingTableWidths {
        alias: max_alias_width(aliased),
        fingerprint: max_fingerprint_width(aliased),
        severity: max_severity_width(findings),
        verdict: max_verdict_width(findings),
        name: max_name_width(findings),
    }
}

fn max_alias_width(aliased: &[(String, Finding)]) -> usize {
    aliased
        .iter()
        .map(|(alias, _)| alias.len())
        .max()
        .unwrap_or(5)
        .max(5)
}

fn max_fingerprint_width(aliased: &[(String, Finding)]) -> usize {
    aliased
        .iter()
        .map(|(_, finding)| short_id(&finding.fingerprint).len())
        .max()
        .unwrap_or(8)
        .max(8)
}

fn max_severity_width(findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| finding.severity.as_str().len())
        .max()
        .unwrap_or(4)
        .max(4)
}

fn max_verdict_width(findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| {
            FindingVerdictFilter::from_finding(finding)
                .as_legacy_str()
                .len()
        })
        .max()
        .unwrap_or(5)
        .max(5)
}

fn max_name_width(findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| finding.title.len())
        .max()
        .unwrap_or(4)
        .max(4)
}

fn finding_table_header(widths: FindingTableWidths) -> Vec<String> {
    vec![
        format!(
            "  {}  {}  {}  {}  {}",
            pad("Alias", widths.alias),
            pad("Fingerprint", widths.fingerprint),
            pad("Sev", widths.severity),
            pad("Check", widths.verdict),
            pad("Name", widths.name)
        ),
        format!(
            "  {}  {}  {}  {}  {}",
            "-".repeat(widths.alias),
            "-".repeat(widths.fingerprint),
            "-".repeat(widths.severity),
            "-".repeat(widths.verdict),
            "-".repeat(widths.name)
        ),
    ]
}

fn finding_table_row(alias: &str, finding: &Finding, widths: FindingTableWidths) -> String {
    format!(
        "  {}  {}  {}  {}  {}",
        pad(alias, widths.alias),
        pad(&short_id(&finding.fingerprint), widths.fingerprint),
        pad(finding.severity.as_str(), widths.severity),
        pad(
            FindingVerdictFilter::from_finding(finding).as_legacy_str(),
            widths.verdict
        ),
        finding.title
    )
}

fn matching_line(report: &FindingListReport) -> String {
    format!(
        "  {} matching (showing {})",
        report.count,
        report.findings.len()
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
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
