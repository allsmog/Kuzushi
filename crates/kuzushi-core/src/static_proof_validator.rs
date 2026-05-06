use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::findings::{StaticProofState, TriageVerdict};
use crate::source_span::{extract_source_span, SourceSpan};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofClaim {
    pub requested_state: StaticProofState,
    #[serde(default)]
    pub source_or_entrypoint_evidence: Vec<StaticProofEvidence>,
    #[serde(default)]
    pub sink_evidence: Vec<StaticProofEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_explanation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_direct_reason: Option<String>,
    pub sanitizer_assessment: StaticProofAssessment,
    pub guard_assessment: StaticProofAssessment,
    #[serde(default)]
    pub citations: Vec<StaticProofCitation>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofEvidence {
    pub label: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub citation: Option<StaticProofCitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofAssessment {
    pub status: StaticProofAssessmentStatus,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StaticProofAssessmentStatus {
    Present,
    Absent,
    NotApplicable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofCitation {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedStaticProofCitation {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofValidation {
    pub accepted: bool,
    pub requested_state: StaticProofState,
    pub final_state: StaticProofState,
    pub final_verdict: TriageVerdict,
    pub issues: Vec<String>,
    pub verified_citations: Vec<VerifiedStaticProofCitation>,
}

impl StaticProofEvidence {
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
            citation: None,
        }
    }

    pub fn with_citation(mut self, citation: StaticProofCitation) -> Self {
        self.citation = Some(citation);
        self
    }
}

impl StaticProofAssessment {
    pub fn new(status: StaticProofAssessmentStatus, explanation: impl Into<String>) -> Self {
        Self {
            status,
            explanation: explanation.into(),
        }
    }
}

impl StaticProofCitation {
    pub fn new(file_path: impl Into<String>, start_line: u32, end_line: u32) -> Self {
        Self {
            file_path: file_path.into(),
            start_line,
            end_line,
            snippet: None,
            snippet_hash: None,
        }
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_snippet_hash(mut self, snippet_hash: impl Into<String>) -> Self {
        self.snippet_hash = Some(snippet_hash.into());
        self
    }
}

pub fn validate_static_proof_claim(
    repo_root: impl AsRef<Path>,
    claim: &StaticProofClaim,
) -> StaticProofValidation {
    let mut issues = Vec::new();
    let mut verified_citations = Vec::new();

    for citation in claim
        .citations
        .iter()
        .chain(
            claim
                .source_or_entrypoint_evidence
                .iter()
                .filter_map(|evidence| evidence.citation.as_ref()),
        )
        .chain(
            claim
                .sink_evidence
                .iter()
                .filter_map(|evidence| evidence.citation.as_ref()),
        )
    {
        match verify_static_proof_citation(repo_root.as_ref(), citation) {
            Ok(verified) => {
                if !verified_citations.contains(&verified) {
                    verified_citations.push(verified);
                }
            }
            Err(error) => issues.push(format!(
                "citation {}:{}-{} is not verified: {error}",
                citation.file_path, citation.start_line, citation.end_line
            )),
        }
    }

    if claim.requested_state == StaticProofState::StaticallyConfirmed {
        validate_confirmed_claim_shape(claim, &verified_citations, &mut issues);
    }

    if contains_forbidden_runtime_claim(claim) {
        issues.push(
            "whitebox-static proof must not claim runtime exploitability or exploit execution"
                .to_string(),
        );
    }

    let accepted = issues.is_empty();
    StaticProofValidation {
        accepted,
        requested_state: claim.requested_state,
        final_state: if accepted {
            claim.requested_state
        } else {
            StaticProofState::NeedsRuntimeEvidence
        },
        final_verdict: if accepted && claim.requested_state == StaticProofState::StaticallyConfirmed
        {
            TriageVerdict::TruePositive
        } else {
            TriageVerdict::NeedsReview
        },
        issues,
        verified_citations,
    }
}

pub fn verify_static_proof_citation(
    repo_root: impl AsRef<Path>,
    citation: &StaticProofCitation,
) -> Result<VerifiedStaticProofCitation> {
    let span = extract_source_span(
        repo_root,
        &citation.file_path,
        citation.start_line,
        citation.end_line,
    )?;
    validate_citation_snippet(&span, citation)?;
    Ok(VerifiedStaticProofCitation {
        file_path: span.file_path,
        start_line: span.start_line,
        end_line: span.end_line,
        snippet_hash: span.content_hash,
    })
}

fn validate_confirmed_claim_shape(
    claim: &StaticProofClaim,
    verified_citations: &[VerifiedStaticProofCitation],
    issues: &mut Vec<String>,
) {
    if claim.source_or_entrypoint_evidence.is_empty() {
        issues.push("statically_confirmed requires source or entrypoint evidence".to_string());
    }
    if claim.sink_evidence.is_empty() {
        issues.push(
            "statically_confirmed requires sink or security-sensitive operation evidence"
                .to_string(),
        );
    }
    if !nonempty_option(&claim.path_explanation) && !nonempty_option(&claim.local_direct_reason) {
        issues.push(
            "statically_confirmed requires a path explanation or local/direct reason".to_string(),
        );
    }
    validate_assessment("sanitizer assessment", &claim.sanitizer_assessment, issues);
    validate_assessment("guard assessment", &claim.guard_assessment, issues);
    if verified_citations.is_empty() {
        issues
            .push("statically_confirmed requires at least one verified code citation".to_string());
    }
    if !has_nonempty(&claim.assumptions) {
        issues.push("statically_confirmed requires explicit assumptions".to_string());
    }
    if !has_nonempty(&claim.missing_evidence) {
        issues
            .push("statically_confirmed requires explicit missing evidence or limits".to_string());
    }
}

fn validate_assessment(label: &str, assessment: &StaticProofAssessment, issues: &mut Vec<String>) {
    if assessment.status == StaticProofAssessmentStatus::Unknown {
        issues.push(format!(
            "statically_confirmed requires known {label} status"
        ));
    }
    if assessment.explanation.trim().is_empty() {
        issues.push(format!("statically_confirmed requires {label} explanation"));
    }
}

fn validate_citation_snippet(span: &SourceSpan, citation: &StaticProofCitation) -> Result<()> {
    if let Some(expected_hash) = citation.snippet_hash.as_deref() {
        if expected_hash != span.content_hash {
            anyhow::bail!(
                "snippet hash mismatch: expected {expected_hash}, found {}",
                span.content_hash
            );
        }
    }
    if let Some(expected_snippet) = citation.snippet.as_deref() {
        if normalize_snippet(expected_snippet) != normalize_snippet(&span.snippet) {
            anyhow::bail!("snippet text does not match cited source lines");
        }
    }
    Ok(())
}

fn contains_forbidden_runtime_claim(claim: &StaticProofClaim) -> bool {
    let mut text = String::new();
    text.push_str(claim.path_explanation.as_deref().unwrap_or_default());
    text.push('\n');
    text.push_str(claim.local_direct_reason.as_deref().unwrap_or_default());
    text.push('\n');
    text.push_str(&claim.sanitizer_assessment.explanation);
    text.push('\n');
    text.push_str(&claim.guard_assessment.explanation);
    for evidence in claim
        .source_or_entrypoint_evidence
        .iter()
        .chain(claim.sink_evidence.iter())
    {
        text.push('\n');
        text.push_str(&evidence.label);
        text.push('\n');
        text.push_str(&evidence.detail);
    }
    for item in claim
        .assumptions
        .iter()
        .chain(claim.missing_evidence.iter())
    {
        text.push('\n');
        text.push_str(item);
    }
    let lower = text.to_ascii_lowercase();
    [
        "runtime exploitable",
        "runtime exploitability",
        "confirmed exploit",
        "exploit executed",
        "poc executed",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn nonempty_option(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn has_nonempty(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

fn normalize_snippet(value: &str) -> String {
    value.replace("\r\n", "\n").trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::static_evidence::static_content_hash;

    use super::*;

    #[test]
    fn static_proof_validator_accepts_fully_cited_confirmed_claim() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            "app.get('/search', requireAuth, (req, res) => {\n  const q = req.query.q;\n  return db.query(`select * from users where name = ${q}`);\n});\n",
        )
        .unwrap();

        let citation = StaticProofCitation::new("src/routes.ts", 1, 3);
        let claim = StaticProofClaim {
            requested_state: StaticProofState::StaticallyConfirmed,
            source_or_entrypoint_evidence: vec![StaticProofEvidence::new(
                "HTTP route",
                "GET /search reads req.query.q",
            )
            .with_citation(citation.clone())],
            sink_evidence: vec![StaticProofEvidence::new(
                "SQL query",
                "db.query receives the route value",
            )
            .with_citation(StaticProofCitation::new("src/routes.ts", 3, 3))],
            path_explanation: Some(
                "The route reads req.query.q and directly interpolates it into db.query."
                    .to_string(),
            ),
            local_direct_reason: None,
            sanitizer_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Absent,
                "No validation or escaping is present between source and sink.",
            ),
            guard_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Present,
                "requireAuth gates the route, so the static claim is authenticated-user scoped.",
            ),
            citations: vec![citation],
            assumptions: vec![
                "Static analysis assumes Express route wiring is reachable.".to_string()
            ],
            missing_evidence: vec![
                "Runtime reachability and exploitability are not assessed in whitebox-static mode."
                    .to_string(),
            ],
        };

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(validation.accepted, "{:?}", validation.issues);
        assert_eq!(
            validation.final_state,
            StaticProofState::StaticallyConfirmed
        );
        assert_eq!(validation.final_verdict, TriageVerdict::TruePositive);
        assert_eq!(validation.verified_citations.len(), 2);
    }

    #[test]
    fn static_proof_validator_downgrades_confirmed_claim_without_required_proof() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("app.ts"), "const x = 1;\n").unwrap();

        let claim = StaticProofClaim {
            requested_state: StaticProofState::StaticallyConfirmed,
            source_or_entrypoint_evidence: Vec::new(),
            sink_evidence: Vec::new(),
            path_explanation: None,
            local_direct_reason: None,
            sanitizer_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Unknown,
                "",
            ),
            guard_assessment: StaticProofAssessment::new(StaticProofAssessmentStatus::Unknown, ""),
            citations: Vec::new(),
            assumptions: Vec::new(),
            missing_evidence: Vec::new(),
        };

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(!validation.accepted);
        assert_eq!(
            validation.final_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert_eq!(validation.final_verdict, TriageVerdict::NeedsReview);
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("source or entrypoint")));
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("sink or security-sensitive")));
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("verified code citation")));
    }

    #[test]
    fn static_proof_validator_rejects_stale_or_fabricated_citations() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("route.ts"), "const q = req.query.q;\n").unwrap();
        let stale_hash = static_content_hash("old source");
        let citation = StaticProofCitation::new("route.ts", 1, 1)
            .with_snippet("const q = req.query.q;")
            .with_snippet_hash(stale_hash);
        let claim = minimally_confirmed_claim(citation);

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(!validation.accepted);
        assert_eq!(
            validation.final_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("snippet hash mismatch")));
    }

    #[test]
    fn static_proof_validator_blocks_runtime_exploitability_language() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("route.ts"), "exec(req.query.cmd);\n").unwrap();
        let citation = StaticProofCitation::new("route.ts", 1, 1);
        let mut claim = minimally_confirmed_claim(citation);
        claim.path_explanation = Some("This is runtime exploitable from the route.".to_string());

        let validation = validate_static_proof_claim(temp.path(), &claim);

        assert!(!validation.accepted);
        assert_eq!(
            validation.final_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert!(validation
            .issues
            .iter()
            .any(|issue| issue.contains("runtime exploitability")));
    }

    fn minimally_confirmed_claim(citation: StaticProofCitation) -> StaticProofClaim {
        StaticProofClaim {
            requested_state: StaticProofState::StaticallyConfirmed,
            source_or_entrypoint_evidence: vec![
                StaticProofEvidence::new("route", "route source").with_citation(citation.clone())
            ],
            sink_evidence: vec![
                StaticProofEvidence::new("sink", "security-sensitive operation")
                    .with_citation(citation.clone()),
            ],
            path_explanation: Some("Source reaches sink in the cited local handler.".to_string()),
            local_direct_reason: None,
            sanitizer_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::Absent,
                "No sanitizer is present in the cited local span.",
            ),
            guard_assessment: StaticProofAssessment::new(
                StaticProofAssessmentStatus::NotApplicable,
                "No authz claim is required for this local static proof.",
            ),
            citations: vec![citation],
            assumptions: vec!["Static call wiring is interpreted from source only.".to_string()],
            missing_evidence: vec!["Runtime execution is intentionally not performed.".to_string()],
        }
    }
}
