//! Recurrence stays inside a context case; the matrix has no mixed denominator.
use super::batch_occurrence::{
    derive_occurrence_from_documents, read_occurrence_queue, BatchOccurrenceReport,
};
use crate::capabilities::campaign::{load_context_matrix_receipt, FrozenContextCase};
use crate::findings::FindingStore;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMatrixOccurrenceReport {
    pub schema_version: u32,
    pub campaign_id: String,
    pub plan_sha256: String,
    pub baseline_case_id: String,
    pub cases: Vec<ContextCaseOccurrenceReport>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCaseOccurrenceReport {
    pub id: String,
    pub label: String,
    pub threat_model_ref: Value,
    pub occurrence: BatchOccurrenceReport,
}

pub fn derive_context_matrix_occurrence_report(
    root: &Path,
    id: &str,
    store: &FindingStore,
) -> Result<ContextMatrixOccurrenceReport> {
    let receipt = load_context_matrix_receipt(root, id)?;
    let plan = crate::capabilities::campaign::read_campaign_plan_document(root, id)?;
    let digest = crate::run_lifecycle::sha256_content_digest(
        &crate::review_yield::domain::canonical_json_bytes(&plan)?,
    );
    anyhow::ensure!(
        digest == receipt.plan_sha256,
        "Context matrix changed during report loading"
    );
    let queue = read_occurrence_queue(root, id)?;
    let cases = receipt
        .matrix
        .cases
        .iter()
        .map(|case| case_occurrence(root, id, &plan, queue.as_ref(), case, store))
        .collect::<Result<Vec<_>>>()?;
    Ok(ContextMatrixOccurrenceReport {
        schema_version: 1,
        campaign_id: id.into(),
        plan_sha256: receipt.plan_sha256,
        baseline_case_id: receipt.matrix.baseline_case_id,
        cases,
    })
}

pub(super) fn case_occurrence(
    root: &Path,
    id: &str,
    plan: &Value,
    queue: Option<&Value>,
    case: &FrozenContextCase,
    store: &FindingStore,
) -> Result<ContextCaseOccurrenceReport> {
    let jobs = plan["jobs"]
        .as_array()
        .context("Context matrix jobs missing")?
        .iter()
        .filter(|job| job["caseId"] == json!(case.id))
        .cloned()
        .collect::<Vec<_>>();
    // An authenticated matrix case projects the same receipt fold as a batch.
    // This document is never published and does not claim single-batch job shape.
    let projection = json!({"batchId":id,"equivalenceKey":case.equivalence.sha256,
        "equivalence":case.equivalence.components,"identityFold":plan.get("identityFold"),
        "jobs":jobs,"trialsPlanned":case.passes,"jobCount":case.passes});
    let occurrence = derive_occurrence_from_documents(
        root,
        id,
        store,
        &projection,
        queue,
        case.equivalence.sha256.clone(),
    )
    .with_context(|| format!("Context case {} has unusable run receipts", case.label))?;
    Ok(ContextCaseOccurrenceReport {
        id: case.id.clone(),
        label: case.label.clone(),
        threat_model_ref: case.base_input["threatModelRef"].clone(),
        occurrence,
    })
}

pub fn read_context_matrix_occurrence_report(
    root: &Path,
    id: &str,
) -> Result<ContextMatrixOccurrenceReport> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let store = FindingStore::open_read_only(workspace.findings_db_path())?;
    derive_context_matrix_occurrence_report(root, id, &store)
}
