//! Dedicated scan-batch planning and launch-equivalence guards.
//!
//! A scan batch deliberately repeats one prepared `sast:scan` operation.
//! It therefore does not share the generic campaign planner's coverage,
//! threat-matrix, or `fillGaps` semantics. The emitted document only reuses
//! the campaign dispatcher's execution schema.

use super::{campaign_plan_path, write_json_atomic};
use crate::modules::ModuleRegistry;
use crate::run_artifacts::RunTargetGitMetadata;
use crate::V2Config;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const SCAN_BATCH_KIND: &str = "scan-batch";
pub const SCAN_BATCH_SCHEMA_VERSION: u32 = 1;
pub const MAX_SCAN_BATCH_TRIALS: usize = 100;
pub const RECEIPTLESS_ATTEMPT_OUTCOME: &str = "abandoned-before-receipt";
const SCAN_TOOL: &str = "sast:scan";

mod child_receipt;
pub(super) mod equivalence;
mod gate;
mod validation;

pub use child_receipt::{
    load_scan_batch_child_equivalence_receipt, verify_scan_batch_child_equivalence,
    ScanBatchChildEquivalenceReceipt, SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
};
pub use equivalence::{capture_batch_equivalence, scan_batch_base_input};
pub use gate::{
    persist_batch_gate_outcome, persist_batch_sarif_document, BatchGateStatus,
    BatchOperationalStatus, BatchSecurityGateStatus, ScanBatchGateBinding, ScanBatchGateCounts,
    ScanBatchGateOutcome, ScanBatchGatePolicy,
};
pub use validation::{validate_scan_batch_execution_plan, ValidatedScanBatchPlan};
mod phase_result;
pub use phase_result::record_scan_batch_phase_result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchEquivalenceKey {
    pub sha256: String,
    pub components: BatchEquivalenceComponents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchEquivalenceComponents {
    pub prepared_input_sha256: String,
    pub workspace_identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_git: Option<RunTargetGitMetadata>,
    pub config_sha256: String,
    pub descriptor_set_sha256: String,
    pub loaded_modules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub runtime_identity: BatchRuntimeIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_model: Option<Value>,
    pub prompt_overrides_sha256: String,
    pub house_rules_sha256: String,
    pub scope_sha256: String,
    pub engine_identity: BatchEngineIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchRuntimeIdentity {
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub config_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchEngineIdentity {
    pub kuzushi_version: String,
    pub requested_selection: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_identity: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanBatchPlanSpec<'a> {
    pub root: &'a Path,
    pub batch_id: Option<String>,
    pub trials: usize,
    pub requested_workers: usize,
    pub gate_policy: ScanBatchGatePolicy,
    pub prepared_input: Value,
    pub config: &'a V2Config,
    pub registry: &'a ModuleRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignPlanHandle {
    pub campaign_id: String,
    pub plan_path: PathBuf,
    pub equivalence_key: BatchEquivalenceKey,
    pub trials_planned: usize,
    pub requested_workers: usize,
    pub effective_workers: usize,
    pub parallel_safety: super::ParallelSafetyResolution,
    pub gate_policy: ScanBatchGatePolicy,
}

pub struct ScanBatchThreatModelLease {
    _lease: crate::capabilities::threat_model::ThreatModelReadLease,
}

pub fn acquire_scan_batch_threat_model_lease(
    root: &Path,
    plan: &ValidatedScanBatchPlan,
) -> Result<ScanBatchThreatModelLease> {
    let expected = plan
        .base_input
        .get("threatModelRef")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("scan-batch threatModelRef is invalid")?;
    let lease = crate::capabilities::threat_model::acquire_exact_threat_model_read_lease(
        root,
        expected.as_ref(),
    )?;
    Ok(ScanBatchThreatModelLease { _lease: lease })
}

pub fn compile_scan_batch_plan(spec: ScanBatchPlanSpec<'_>) -> Result<CampaignPlanHandle> {
    compile_batch_plan(spec, false, None, None)
}

#[cfg(test)]
pub(super) fn compile_study_plan(
    spec: ScanBatchPlanSpec<'_>,
    investigation: Option<&str>,
) -> Result<CampaignPlanHandle> {
    compile_batch_plan(spec, true, investigation, None)
}

pub(super) fn compile_study_plan_with_baseline(
    spec: ScanBatchPlanSpec<'_>,
    investigation: Option<&str>,
    baseline: Option<&str>,
) -> Result<CampaignPlanHandle> {
    if let Some(run) = baseline {
        crate::run_artifacts::resolve_run_artifact_path(spec.root, run, "run.json")?;
    }
    compile_batch_plan(spec, true, investigation, baseline)
}

fn compile_batch_plan(
    spec: ScanBatchPlanSpec<'_>,
    requires_work_approval: bool,
    investigation: Option<&str>,
    baseline: Option<&str>,
) -> Result<CampaignPlanHandle> {
    validate_trial_count(spec.trials)?;
    let batch_id = spec.batch_id.clone().unwrap_or_else(generated_batch_id);
    validate_scan_batch_id(&batch_id)?;
    let (base_input, _context_lease) = prepare_batch_scan_input(&spec)?;
    let parallel_safety = batch_parallel_safety(&spec, &base_input)?;
    let equivalence_key =
        capture_batch_equivalence(spec.root, &base_input, spec.config, spec.registry)?;
    let mut plan = scan_batch_plan_document(
        &batch_id,
        spec.trials,
        &base_input,
        &equivalence_key,
        &parallel_safety,
        &spec.gate_policy,
    );
    bind_study_metadata(&mut plan, requires_work_approval, investigation, baseline)?;
    let plan_path = campaign_plan_path(spec.root, &batch_id);
    anyhow::ensure!(
        !plan_path.exists(),
        "scan batch {batch_id:?} already has an immutable plan"
    );
    write_json_atomic(&plan_path, &plan)?;
    Ok(CampaignPlanHandle {
        campaign_id: batch_id,
        plan_path,
        equivalence_key,
        trials_planned: spec.trials,
        requested_workers: parallel_safety.requested_workers,
        effective_workers: parallel_safety.effective_workers,
        parallel_safety,
        gate_policy: spec.gate_policy,
    })
}

fn prepare_batch_scan_input(
    spec: &ScanBatchPlanSpec<'_>,
) -> Result<(
    Value,
    crate::capabilities::threat_model::ThreatModelReadLease,
)> {
    let mut input = scan_batch_base_input(spec.prepared_input.clone());
    let lease = acquire_plan_threat_model_lease(spec.root, &spec.prepared_input)?;
    equivalence::force_discovery_only(&mut input)?;
    bind_threat_model_ref(&mut input, lease.model_ref())?;
    Ok((input, lease))
}

fn bind_study_metadata(
    plan: &mut Value,
    required: bool,
    investigation: Option<&str>,
    baseline: Option<&str>,
) -> Result<()> {
    if !required {
        return Ok(());
    }
    plan["requiresWorkApproval"] = Value::Bool(true);
    if let Some(id) = investigation {
        validate_scan_batch_id(id)?;
        plan["investigationId"] = Value::String(id.into());
    }
    if let Some(run) = baseline {
        plan["resourceBaselineRunId"] = json!(run);
    }
    Ok(())
}

fn acquire_plan_threat_model_lease(
    root: &Path,
    input: &Value,
) -> Result<crate::capabilities::threat_model::ThreatModelReadLease> {
    use crate::capabilities::threat_model::{
        acquire_exact_threat_model_read_lease, acquire_threat_model_read_lease,
        open_writable_threat_model_store, ThreatModelSelection,
    };
    match ThreatModelSelection::from_input(input)? {
        ThreatModelSelection::Active => {
            open_writable_threat_model_store(root)?;
            acquire_threat_model_read_lease(root)
        }
        ThreatModelSelection::None => acquire_exact_threat_model_read_lease(root, None),
        ThreatModelSelection::Revision(reference) => {
            acquire_exact_threat_model_read_lease(root, Some(&reference))
        }
    }
}

fn batch_parallel_safety(
    spec: &ScanBatchPlanSpec<'_>,
    input: &Value,
) -> Result<super::ParallelSafetyResolution> {
    let mut resolution =
        super::resolve_parallel_safety(spec.registry, SCAN_TOOL, input, spec.requested_workers)?;
    if resolution.effective_workers > spec.trials {
        resolution.effective_workers = spec.trials;
        resolution.clamp_reason = Some(format!(
            "effective workers limited to {} planned logical trials",
            spec.trials
        ));
    }
    Ok(resolution)
}

fn bind_threat_model_ref(
    input: &mut Value,
    model_ref: Option<&crate::capabilities::threat_model::ThreatModelRef>,
) -> Result<()> {
    let object = input
        .as_object_mut()
        .context("prepared sast:scan input must be an object")?;
    object.remove("threat_model_ref");
    object.insert(
        "threatModelRef".to_string(),
        serde_json::to_value(model_ref)?,
    );
    Ok(())
}

fn scan_batch_plan_document(
    batch_id: &str,
    trials: usize,
    base_input: &Value,
    equivalence_key: &BatchEquivalenceKey,
    parallel_safety: &super::ParallelSafetyResolution,
    gate_policy: &ScanBatchGatePolicy,
) -> Value {
    let jobs = (1..=trials)
        .map(|trial| scan_batch_job(batch_id, trial, base_input, &equivalence_key.sha256))
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": SCAN_BATCH_SCHEMA_VERSION,
        "kind": SCAN_BATCH_KIND,
        "campaignId": batch_id,
        "batchId": batch_id,
        "tool": SCAN_TOOL,
        "createdAtMs": epoch_ms(),
        "trialsPlanned": trials,
        "jobCount": trials,
        "workers": parallel_safety.effective_workers,
        "requestedWorkers": parallel_safety.requested_workers,
        "effectiveWorkers": parallel_safety.effective_workers,
        "parallelSafety": parallel_safety,
        "gatePolicy": gate_policy,
        "fillGaps": false,
        "coverageBypassed": true,
        "identityFold": base_input.get("identityFold").and_then(Value::as_str).unwrap_or("legacy"),
        "equivalenceKey": equivalence_key.sha256,
        "equivalence": equivalence_key.components,
        "baseInput": base_input,
        "jobs": jobs,
    })
}

pub(super) fn scan_batch_job(
    batch_id: &str,
    trial: usize,
    base_input: &Value,
    equivalence_key: &str,
) -> Value {
    let trial_id = format!("trial-{trial:03}");
    let mut input = base_input.as_object().cloned().unwrap_or_default();
    input.insert("batchId".to_string(), json!(batch_id));
    input.insert("trial".to_string(), json!(trial));
    input.insert("batchEquivalenceKey".to_string(), json!(equivalence_key));
    json!({
        "jobId": trial_id,
        "trial": trial,
        "logicalTrialId": format!("{batch_id}-trial-{trial:03}"),
        "tool": SCAN_TOOL,
        "priority": 0,
        "state": "planned",
        "equivalenceKey": equivalence_key,
        "input": Value::Object(input),
    })
}

fn validate_trial_count(trials: usize) -> Result<()> {
    anyhow::ensure!(trials >= 2, "scan batches require at least 2 trials");
    anyhow::ensure!(
        trials <= MAX_SCAN_BATCH_TRIALS,
        "--trials exceeds the hard cap of {MAX_SCAN_BATCH_TRIALS}"
    );
    Ok(())
}

pub fn validate_scan_batch_id(batch_id: &str) -> Result<()> {
    anyhow::ensure!(
        !batch_id.is_empty()
            && batch_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "batch id may only contain ASCII alphanumerics, '-', and '_'"
    );
    Ok(())
}

fn generated_batch_id() -> String {
    let uuid = uuid::Uuid::new_v4().simple().to_string();
    format!("batch-{}", &uuid[..8])
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
