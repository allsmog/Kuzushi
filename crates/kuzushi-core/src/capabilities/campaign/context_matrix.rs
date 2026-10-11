//! A finite set of context cases executed by the existing campaign dispatcher.
use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use serde::{Deserialize, Serialize};
use serde_json::json;

mod approval;
mod domain;
mod planning;
mod scope_comparison;
mod validation;
pub(super) use approval::review_for_approval;
pub use domain::{ContextCaseInput, ContextMatrixDraft, MAX_CONTEXT_CASES};
pub(crate) use planning::compile_context_matrix;
pub use validation::{load_context_matrix_receipt, validate_context_matrix_plan};

pub const CONTEXT_MATRIX_KIND: &str = "context-matrix";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenContextCase {
    pub id: String,
    pub label: String,
    pub passes: usize,
    pub base_input: Value,
    pub equivalence: BatchEquivalenceKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omission_scope_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextMatrixMetadataV1 {
    pub schema_version: u32,
    pub baseline_case_id: String,
    pub cases: Vec<FrozenContextCase>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextMatrixReceipt {
    pub schema_version: u32,
    pub campaign_id: String,
    pub investigation_id: Option<String>,
    pub plan_path: PathBuf,
    pub plan_sha256: String,
    pub workers: usize,
    pub requested_workers: usize,
    pub worker_limitation: Option<String>,
    pub job_count: usize,
    pub matrix: ContextMatrixMetadataV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supporting_context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_evidence: Option<StudyResourceEvidenceV1>,
}

impl ContextMatrixMetadataV1 {
    pub fn baseline(&self) -> Result<&FrozenContextCase> {
        self.cases
            .iter()
            .find(|case| case.id == self.baseline_case_id)
            .context("Context matrix baseline is missing")
    }
}

impl ContextMatrixReceipt {
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

pub(crate) fn context_case_job(campaign: &str, case: &FrozenContextCase, trial: usize) -> Value {
    let mut job =
        batch::scan_batch_job(campaign, trial, &case.base_input, &case.equivalence.sha256);
    let id = format!("{}-trial-{trial:03}", case.id);
    job["jobId"] = json!(id);
    job["caseId"] = json!(case.id);
    job["logicalTrialId"] = json!(format!("{campaign}-{id}"));
    job
}

#[cfg(test)]
mod tests;
