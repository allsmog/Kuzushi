use super::*;

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
