//! Explicit accepted scope cases use the existing finite campaign dispatcher.
use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::workspace::{ScanScopeProposalRef, ScanScopeRef};
use serde::{Deserialize, Serialize};
use serde_json::json;

mod domain;
mod planning;
mod validation;
pub use domain::{ScopeStudyCaseInput, ScopeStudyDraft};
pub(crate) use planning::compile_scope_study;
pub(super) use validation::review_for_approval;
pub use validation::{load_scope_study_receipt, validate_scope_study_plan};

pub const SCOPE_STUDY_KIND: &str = "scope-study";

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeStudyMetadataV1 {
    pub schema_version: u32,
    pub proposal_ref: ScanScopeProposalRef,
    pub cases: Vec<FrozenContextCase>,
    pub selections: Vec<ScopeStudyCaseInput>,
    pub inherited_threat_model_ref: Value,
    pub unplanned_scope_ids: Vec<String>,
}

impl ScopeStudyMetadataV1 {
    pub fn first(&self) -> Result<&FrozenContextCase> {
        self.cases
            .first()
            .context("Scope study has no discovery cases")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeStudyReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub campaign_id: String,
    pub investigation_id: Option<String>,
    pub plan_path: PathBuf,
    pub plan_sha256: String,
    pub workers: usize,
    pub requested_workers: usize,
    pub worker_limitation: Option<String>,
    pub job_count: usize,
    pub scope_study: ScopeStudyMetadataV1,
    pub supporting_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_evidence: Option<StudyResourceEvidenceV1>,
}

impl ScopeStudyReceipt {
    pub fn load_allowance(
        &self,
        root: &Path,
    ) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
        if let Some(id) = &self.investigation_id {
            return super::study_receipt::load_investigation_allowance(root, id);
        }
        crate::SpendLimiter::read_campaign_allowance(
            &crate::WorkspaceTarget::new(root)?.findings_db_path(),
            &self.campaign_id,
        )
    }
}
