use crate::run_artifacts::RunSummary;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFindingExportRecord {
    pub alias: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    pub fingerprint: String,
    pub kind: String,
    pub rule_id: String,
    pub title: String,
    pub location: WorkspaceFindingExportLocation,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub priority: String,
    pub lifecycle_status: String,
    pub review_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_conflict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage_verdict: Option<String>,
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snoozed_until: Option<String>,
    pub evidence: WorkspaceEvidenceExportSummary,
    pub analysis: WorkspaceAnalysisExportSummary,
    pub static_proof_state: String,
    pub static_proof_label: String,
    /// Coarse proof/confidence band derived from the same state that governs
    /// verification (`confirmed` | `likely` | `unverified` | `dismissed`). A
    /// first-class axis distinct from `severity`, made explicit so consumers do
    /// not have to re-derive it from the granular proof fields.
    pub proof_confidence: String,
    pub verification: WorkspaceVerificationExportSummary,
    pub tool: String,
    pub vuln_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_signature: Option<String>,
    pub corroboration_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub provenance: WorkspaceFindingProvenanceSummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFindingExportLocation {
    pub file: String,
    pub start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceEvidenceExportSummary {
    pub state: String,
    pub observed_evidence_present: bool,
    pub observed_count: usize,
    pub observed_code_count: usize,
    pub observed_capture_count: usize,
    pub observed_other_count: usize,
    pub model_generated_reasoning_present: bool,
    pub model_generated_reasoning_count: usize,
    pub derived_source_present: bool,
    pub source_count: usize,
    pub raw_http_blob_present: bool,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceAnalysisExportSummary {
    pub static_proof_recorded: bool,
    pub automated_reasoning_present: bool,
    pub human_review_present: bool,
    pub imported_review_present: bool,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceVerificationExportSummary {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFindingProvenanceSummary {
    pub tool: String,
    pub vuln_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_signature: Option<String>,
    pub corroboration_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kuzushi_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_platform: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceRunExportContext {
    pub status: Option<String>,
    pub kuzushi_version: Option<String>,
    pub model: Option<String>,
    pub runtime_platform: Option<String>,
}

impl WorkspaceRunExportContext {
    pub fn from_summary(summary: &RunSummary) -> Self {
        Self {
            status: non_empty_string(&summary.status),
            kuzushi_version: summary.kuzushi_version.clone(),
            model: summary.model.clone(),
            runtime_platform: summary.platform.clone(),
        }
    }
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
