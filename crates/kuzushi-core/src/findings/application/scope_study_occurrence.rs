//! Recurrence is measured within each accepted scope, never across siblings.
use super::batch_occurrence::read_occurrence_queue;
use super::context_matrix_occurrence::{case_occurrence, ContextCaseOccurrenceReport};
use crate::capabilities::campaign::load_scope_study_receipt;
use crate::findings::FindingStore;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeStudyOccurrenceReport {
    pub schema_version: u32,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub cases: Vec<ContextCaseOccurrenceReport>,
}

pub fn derive_scope_study_occurrence_report(
    root: &Path,
    id: &str,
    store: &FindingStore,
) -> Result<ScopeStudyOccurrenceReport> {
    let receipt = load_scope_study_receipt(root, id)?;
    let plan = crate::capabilities::campaign::read_campaign_plan_document(root, id)?;
    let digest = crate::run_lifecycle::sha256_content_digest(
        &crate::review_yield::domain::canonical_json_bytes(&plan)?,
    );
    anyhow::ensure!(
        digest == receipt.plan_sha256,
        "Scope study changed during report loading"
    );
    let queue = read_occurrence_queue(root, id)?;
    let cases = receipt
        .scope_study
        .cases
        .iter()
        .map(|case| case_occurrence(root, id, &plan, queue.as_ref(), case, store))
        .collect::<Result<Vec<_>>>()?;
    Ok(ScopeStudyOccurrenceReport {
        schema_version: 1,
        campaign_id: id.into(),
        plan_sha256: receipt.plan_sha256,
        cases,
    })
}

pub fn read_scope_study_occurrence_report(
    root: &Path,
    id: &str,
) -> Result<ScopeStudyOccurrenceReport> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let store = FindingStore::open_read_only(workspace.findings_db_path())?;
    derive_scope_study_occurrence_report(root, id, &store)
}
