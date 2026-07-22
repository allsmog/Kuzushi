use anyhow::{Context, Result};
use kuzushi_core::{Finding, FindingEvidence};
use serde::Serialize;

const TRIAGE_MESSAGE_LIMIT: usize = 2_000;
const TRIAGE_TITLE_LIMIT: usize = 300;
const TRIAGE_EVIDENCE_LIMIT: usize = 5;
const TRIAGE_EVIDENCE_TEXT_LIMIT: usize = 600;

pub(crate) fn compact_triage_prompt(finding: &Finding, template: Option<&str>) -> Result<String> {
    let compact = CompactTriageFinding::from_finding(finding);
    let json = serde_json::to_string(&compact).context("Could not serialize finding")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(kuzushi_core::runtime::DEFAULT_TRIAGE_PROMPT);
    Ok(format!(
        "{prefix}\n\nUNTRUSTED_DERIVED_FINDING_BEGIN\nFinding JSON:\n{json}\nUNTRUSTED_DERIVED_FINDING_END"
    ))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompactTriageFinding {
    fingerprint: String,
    rule_id: String,
    title: String,
    severity: String,
    location: CompactFindingLocation,
    message: String,
    tool: String,
    static_proof_state: Option<String>,
    /// Producer-claimed attacker preconditions — cross-check the claimed
    /// severity against these; the write-time ceiling already capped it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    preconditions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exploit_scenario: Option<String>,
    evidence: Vec<CompactFindingEvidence>,
}

impl CompactTriageFinding {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            title: cap_chars(&finding.title, TRIAGE_TITLE_LIMIT),
            severity: finding.severity.as_str().to_string(),
            location: CompactFindingLocation::from_finding(finding),
            message: cap_chars(&finding.message, TRIAGE_MESSAGE_LIMIT),
            tool: finding.tool.clone(),
            static_proof_state: finding
                .static_proof_state
                .map(|state| state.as_str().to_string()),
            preconditions: finding.preconditions.clone(),
            impact: finding
                .impact
                .as_deref()
                .map(|impact| cap_chars(impact, TRIAGE_EVIDENCE_TEXT_LIMIT)),
            exploit_scenario: finding
                .exploit_scenario
                .as_deref()
                .map(|scenario| cap_chars(scenario, TRIAGE_EVIDENCE_TEXT_LIMIT)),
            evidence: finding
                .evidence
                .iter()
                .take(TRIAGE_EVIDENCE_LIMIT)
                .map(CompactFindingEvidence::from_evidence)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompactFindingLocation {
    file_path: String,
    start_line: u32,
    end_line: Option<u32>,
}

impl CompactFindingLocation {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            file_path: finding.file_path.clone(),
            start_line: finding.start_line,
            end_line: finding.end_line,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompactFindingEvidence {
    kind: String,
    file_path: String,
    line: u32,
    snippet: String,
    rationale: String,
    confidence: u8,
    request_blob_present: bool,
    response_blob_present: bool,
}

impl CompactFindingEvidence {
    fn from_evidence(evidence: &FindingEvidence) -> Self {
        Self {
            kind: evidence.kind.clone(),
            file_path: evidence.file_path.clone(),
            line: evidence.line,
            snippet: cap_chars(&evidence.snippet, TRIAGE_EVIDENCE_TEXT_LIMIT),
            rationale: cap_chars(&evidence.rationale, TRIAGE_EVIDENCE_TEXT_LIMIT),
            confidence: evidence.confidence,
            request_blob_present: evidence.request_blob.is_some(),
            response_blob_present: evidence.response_blob.is_some(),
        }
    }
}

fn cap_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut capped = value.chars().take(max_chars).collect::<String>();
    capped.push_str("...");
    capped
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, Severity};

    #[test]
    fn compact_triage_prompt_omits_raw_http_blobs() {
        let mut finding = Finding::new_tool(
            "burp",
            "http-request",
            "captures/login.har",
            1,
            Some(1),
            Severity::High,
            &"x".repeat(TRIAGE_MESSAGE_LIMIT + 200),
        );
        finding.evidence.push(FindingEvidence {
            kind: "http-request".to_string(),
            file_path: "captures/login.har".to_string(),
            line: 1,
            snippet: "POST /login".to_string(),
            rationale: "raw traffic confirms the route".to_string(),
            confidence: 90,
            request_blob: Some("SECRET REQUEST BODY".to_string()),
            response_blob: Some("SECRET RESPONSE BODY".to_string()),
        });

        let prompt = compact_triage_prompt(&finding, None).unwrap();

        assert!(prompt.contains("\"requestBlobPresent\":true"));
        assert!(prompt.contains("\"responseBlobPresent\":true"));
        assert!(!prompt.contains("SECRET REQUEST BODY"));
        assert!(!prompt.contains("SECRET RESPONSE BODY"));
        assert!(prompt.contains(&format!("{}...", "x".repeat(TRIAGE_MESSAGE_LIMIT))));
        assert!(!prompt.contains(&"x".repeat(TRIAGE_MESSAGE_LIMIT + 1)));
    }
}
