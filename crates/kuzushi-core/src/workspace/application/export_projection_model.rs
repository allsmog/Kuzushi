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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    pub location: WorkspaceFindingExportLocation,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub priority: String,
    pub lifecycle_status: String,
    pub review_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_gap: Option<crate::findings::FindingObservationGap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_note: Option<String>,
    /// Operator-facing triage-lifecycle state derived from the latest human
    /// decision. Observation presence is separate and never establishes a fix.
    pub triage_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dismissal: Option<WorkspaceDismissalExportSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_conflict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_author: Option<String>,
    /// The observed run and source snapshot the latest decision was made
    /// against, and whether the finding was seen on different source since.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_decision_basis: Option<super::WorkspaceReviewDecisionBasis>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<WorkspaceRemediationExportSummary>,
    /// Producer-supplied fix prose (`Finding.remediation`), distinct from the
    /// patch-lifecycle `remediation` summary above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_scenario: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub preconditions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRemediationExportSummary {
    pub application_id: String,
    pub patch_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_scan_id: Option<String>,
    pub application_state: String,
    pub empirically_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverify_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverify_run_id: Option<String>,
    pub diff_hash: String,
    pub touched_paths: Vec<String>,
}

impl From<&crate::findings::PatchLifecycleRecord> for WorkspaceRemediationExportSummary {
    fn from(record: &crate::findings::PatchLifecycleRecord) -> Self {
        let reverify_outcome = matches!(
            record.state,
            crate::findings::PatchLifecycleState::Verified
                | crate::findings::PatchLifecycleState::StillVulnerable
                | crate::findings::PatchLifecycleState::NotRediscovered
                | crate::findings::PatchLifecycleState::Inconclusive
                | crate::findings::PatchLifecycleState::Failed
                | crate::findings::PatchLifecycleState::Interrupted
                | crate::findings::PatchLifecycleState::ChangedSinceApply
        )
        .then(|| record.state.as_str().to_string());
        Self {
            application_id: record.application_id.clone(),
            patch_run_id: record.patch_run_id.clone(),
            finding_scan_id: record.finding_scan_id.clone(),
            application_state: record.state.as_str().to_string(),
            empirically_verified: record.is_empirically_verified(),
            reverify_outcome,
            reverify_run_id: record.reverify_run_id.clone(),
            diff_hash: record.diff_hash.clone(),
            touched_paths: record.touched_paths().map(str::to_string).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceDismissalExportSummary {
    pub reason: String,
    pub note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
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
    /// Highest per-evidence confidence, when any evidence row carries one.
    /// External-ledger imports store their verdict-derived confidence here
    /// Input validation maps legacy verdicts here (e.g. VALIDATED→90,
    /// REFUTED→10), which is otherwise summarized away.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_confidence_max: Option<u8>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<crate::workflow_attempts::TargetContentIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproducer: Option<crate::content_store::ObjectRef>,
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
