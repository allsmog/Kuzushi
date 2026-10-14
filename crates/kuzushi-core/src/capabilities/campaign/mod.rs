//! Deterministic campaign planning over threat-model × shard × model axes.
//!
//! `campaign:plan` crosses the persisted threat model (or a directory of
//! subsystem models) with the shard manifest and optional model list into a
//! ranked job matrix at `.kuzushi/v3/campaigns/<id>/plan.json`, materializing
//! one prompt seasoning file per threat-scoped job. `campaign:status` folds
//! the plan with the dispatcher queue state (`queue.json`, written by
//! `kuzushi campaign run`) and run `done.json` sentinels into one view.
//! Neither tool calls a model: planning is pure workspace-file computation.

mod allowance;
mod approved_work;
mod batch;
mod brief;
pub use approved_work::read_bounded_plan as read_campaign_plan_document;
pub use approved_work::validate_campaign_report_approval;
pub use brief::load_plan_brief;
pub use brief::{
    execute_brief, load_brief, load_current_brief, BriefDocument, BriefGuidanceV1, BriefReference,
    BriefRevision, MAX_BRIEF_TEXT_BYTES,
};
mod context_experiment;
mod context_matrix;
mod scan_cases;
mod scope_study;
pub use scope_study::{
    load_scope_study_receipt, validate_scope_study_plan, ScopeStudyCaseInput, ScopeStudyDraft,
    ScopeStudyMetadataV1, ScopeStudyReceipt, SCOPE_STUDY_KIND,
};
pub mod coverage;
mod dispatcher_control;
mod dispatcher_lease;
pub use dispatcher_control::{
    read_campaign_dispatcher_error, request_campaign_dispatcher_stop, CampaignDispatcherControl,
};
mod map_allowance;
mod parallel_safety;
mod plan;
mod prior_runs;
mod shards;
pub mod snapshot;
mod status;
mod study_plan;
pub use context_experiment::{load_study_context_experiment, ContextExperimentReceipt};
pub use context_matrix::{
    load_context_matrix_receipt, validate_context_matrix_plan, ContextCaseInput,
    ContextMatrixDraft, ContextMatrixMetadataV1, ContextMatrixReceipt, FrozenContextCase,
    CONTEXT_MATRIX_KIND, MAX_CONTEXT_CASES,
};
mod study_receipt;
mod study_resources;
pub use map_allowance::{load_accepted_map_allowance, load_selected_map_history_allowance};
pub use study_resources::campaign_preview::{
    CaseResourceEvidenceV1, ResourceScenario, StudyResourceEvidenceV1,
};
pub use study_resources::catalogue::{
    load_named_scan_usage, load_scan_usage_catalogue, ScanUsageCatalogue, SCAN_USAGE_HISTORY_LIMIT,
};
pub use study_resources::study_catalogue::{
    load_study_usage_catalogue, StudyUsageCatalogue, StudyUsageChoice, STUDY_HISTORY_CHOICE_LIMIT,
    STUDY_HISTORY_ENTRY_LIMIT,
};
pub use study_resources::{
    load_scan_resource_evidence, ScanResourceEvidence, StudyResourceProjection,
};
mod context_study;
mod scope_allowance;
pub use context_study::{
    execute_context_map, execute_context_study, load_context_study, scope_proposal_study_input,
    ContextPreparationJob, ContextStudyReceipt, RejectedContextOutput, ScopeStudyOriginV1,
};
pub use scope_allowance::load_scope_proposal_allowance;
pub use study_receipt::{
    load_study_allowance, load_study_plan_receipt, load_study_resource_baseline, StudyPlanReceipt,
};
#[cfg(test)]
mod tests;
mod threats;
pub mod trend;
pub mod trend_history;

pub use allowance::{execute_allowance_status, execute_approve_allowance};
pub(crate) use approved_work::require_study_reference;
pub use approved_work::{campaign_plan_digest, work_input_digest};
pub use batch::{
    acquire_scan_batch_threat_model_lease, capture_batch_equivalence, compile_scan_batch_plan,
    load_scan_batch_child_equivalence_receipt, persist_batch_gate_outcome,
    persist_batch_sarif_document, record_scan_batch_phase_result, scan_batch_base_input,
    validate_scan_batch_execution_plan, validate_scan_batch_id,
    verify_scan_batch_child_equivalence, BatchEquivalenceComponents, BatchEquivalenceKey,
    BatchGateStatus, BatchOperationalStatus, BatchSecurityGateStatus, CampaignPlanHandle,
    ScanBatchChildEquivalenceReceipt, ScanBatchGateBinding, ScanBatchGateCounts,
    ScanBatchGateOutcome, ScanBatchGatePolicy, ScanBatchPlanSpec, ScanBatchThreatModelLease,
    ValidatedScanBatchPlan, MAX_SCAN_BATCH_TRIALS, RECEIPTLESS_ATTEMPT_OUTCOME,
    SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE, SCAN_BATCH_KIND, SCAN_BATCH_SCHEMA_VERSION,
};
pub use coverage::execute_campaign_coverage;
pub use dispatcher_lease::{
    acquire_batch_controller_lease, acquire_dispatcher_lease, BatchControllerLease,
    CampaignDispatcherLease,
};
pub use parallel_safety::{
    resolve_parallel_safety, ParallelSafety, ParallelSafetyResolution, ScanTaskParallelClaim,
    MAX_CAMPAIGN_WORKERS,
};
pub use plan::execute_campaign_plan;
pub use status::execute_campaign_status;
pub use study_plan::execute_study_plan;

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub const CAMPAIGNS_DIR: &str = "campaigns";
pub const CAMPAIGN_PLAN_FILE: &str = "plan.json";
pub const CAMPAIGN_QUEUE_FILE: &str = "queue.json";

pub fn campaigns_dir(root: &Path) -> PathBuf {
    crate::workspace::workspace_state_dir(root).join(CAMPAIGNS_DIR)
}

pub fn campaign_dir(root: &Path, campaign_id: &str) -> PathBuf {
    campaigns_dir(root).join(campaign_id)
}

pub fn campaign_plan_path(root: &Path, campaign_id: &str) -> PathBuf {
    campaign_dir(root, campaign_id).join(CAMPAIGN_PLAN_FILE)
}

pub fn campaign_queue_path(root: &Path, campaign_id: &str) -> PathBuf {
    campaign_dir(root, campaign_id).join(CAMPAIGN_QUEUE_FILE)
}

/// Durable atomic JSON publish. Readers never observe a partial document.
fn write_json_atomic(path: &Path, document: &Value) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    let body = serde_json::to_string_pretty(document).context("Could not serialize document")?;
    crate::fs_atomic::write_atomic(path, &body)
        .with_context(|| format!("Could not publish {}", path.display()))?;
    Ok(())
}

fn read_json_file(path: &Path) -> Result<Value> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("{} is malformed JSON", path.display()))
}

fn string_input(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

fn string_list_input(input: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(string_list_value)
        .unwrap_or_default()
}

fn string_list_value(value: &Value) -> Option<Vec<String>> {
    if let Some(items) = value.as_array() {
        return Some(collect_non_empty(items.iter().filter_map(Value::as_str)));
    }
    value.as_str().map(|csv| collect_non_empty(csv.split(',')))
}

fn collect_non_empty<'a>(items: impl Iterator<Item = &'a str>) -> Vec<String> {
    items
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn usize_input(input: &Value, keys: &[&str], default: usize) -> usize {
    keys.iter()
        .filter_map(|key| input.get(*key))
        .find_map(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(default)
}
