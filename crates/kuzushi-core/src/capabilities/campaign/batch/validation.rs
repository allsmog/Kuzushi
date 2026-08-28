//! Authentication of immutable scan-batch execution plans.

use super::equivalence::{digest_serializable, scan_batch_base_input};
use super::{
    scan_batch_job, BatchEquivalenceComponents, ScanBatchGatePolicy, SCAN_BATCH_KIND,
    SCAN_BATCH_SCHEMA_VERSION,
};
use crate::capabilities::campaign::ParallelSafetyResolution;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedScanBatchPlan {
    pub batch_id: String,
    pub equivalence_key: String,
    pub base_input: Value,
    pub trials_planned: usize,
    pub requested_workers: usize,
    pub effective_workers: usize,
    pub gate_policy: ScanBatchGatePolicy,
}

pub fn validate_scan_batch_execution_plan(
    batch_id: &str,
    plan: &Value,
) -> Result<ValidatedScanBatchPlan> {
    validate_plan_header(batch_id, plan)?;
    let base_input = required_value(plan, "baseInput")?;
    validate_base_input(&base_input)?;
    let equivalence_key = required_string(plan, "equivalenceKey")?;
    validate_equivalence_receipt(plan, &base_input, &equivalence_key)?;
    let trials_planned = required_usize(plan, "trialsPlanned")?;
    validate_jobs(
        plan,
        batch_id,
        trials_planned,
        &base_input,
        &equivalence_key,
    )?;
    let (requested_workers, effective_workers) = validate_worker_receipt(plan, trials_planned)?;
    let gate_policy = serde_json::from_value(required_value(plan, "gatePolicy")?)
        .context("scan-batch plan has an invalid gatePolicy")?;
    Ok(ValidatedScanBatchPlan {
        batch_id: batch_id.to_string(),
        equivalence_key,
        base_input,
        trials_planned,
        requested_workers,
        effective_workers,
        gate_policy,
    })
}

fn validate_plan_header(batch_id: &str, plan: &Value) -> Result<()> {
    anyhow::ensure!(
        plan.get("schemaVersion").and_then(Value::as_u64) == Some(SCAN_BATCH_SCHEMA_VERSION.into()),
        "scan-batch plan has an unsupported schemaVersion"
    );
    for key in ["campaignId", "batchId"] {
        anyhow::ensure!(
            plan.get(key).and_then(Value::as_str) == Some(batch_id),
            "scan-batch plan {key} disagrees with {batch_id:?}"
        );
    }
    anyhow::ensure!(
        plan.get("kind").and_then(Value::as_str) == Some(SCAN_BATCH_KIND)
            && plan.get("tool").and_then(Value::as_str) == Some("sast:scan"),
        "campaign {batch_id:?} is not an executable sast:scan batch"
    );
    anyhow::ensure!(
        plan.get("fillGaps").and_then(Value::as_bool) == Some(false)
            && plan.get("coverageBypassed").and_then(Value::as_bool) == Some(true),
        "scan-batch plan must bypass coverage and fillGaps"
    );
    Ok(())
}

fn validate_base_input(base_input: &Value) -> Result<()> {
    anyhow::ensure!(
        base_input.is_object(),
        "scan-batch baseInput must be an object"
    );
    let threat_model_ref = base_input.get("threatModelRef").cloned();
    let mut normalized = scan_batch_base_input(base_input.clone());
    if let (Some(reference), Some(object)) = (threat_model_ref, normalized.as_object_mut()) {
        object.insert("threatModelRef".to_string(), reference);
    }
    anyhow::ensure!(
        normalized == *base_input,
        "scan-batch baseInput contains mutable trial provenance"
    );
    Ok(())
}

fn validate_equivalence_receipt(plan: &Value, base_input: &Value, key: &str) -> Result<()> {
    let components: BatchEquivalenceComponents =
        serde_json::from_value(required_value(plan, "equivalence")?)
            .context("scan-batch plan has an invalid equivalence receipt")?;
    anyhow::ensure!(
        digest_serializable(&components)? == key,
        "scan-batch equivalenceKey does not authenticate its receipt"
    );
    anyhow::ensure!(
        digest_serializable(base_input)? == components.prepared_input_sha256,
        "scan-batch baseInput does not match preparedInputSha256"
    );
    validate_threat_model_binding(base_input, &components)
}

fn validate_threat_model_binding(
    base_input: &Value,
    components: &BatchEquivalenceComponents,
) -> Result<()> {
    let bound = base_input
        .get("threatModelRef")
        .filter(|value| !value.is_null());
    let captured = components
        .threat_model
        .as_ref()
        .filter(|value| value.get("legacySha256").is_none());
    anyhow::ensure!(
        bound == captured,
        "scan-batch threatModelRef disagrees with its equivalence receipt"
    );
    Ok(())
}

fn validate_jobs(
    plan: &Value,
    batch_id: &str,
    trials: usize,
    base_input: &Value,
    equivalence_key: &str,
) -> Result<()> {
    let jobs = plan
        .get("jobs")
        .and_then(Value::as_array)
        .context("scan-batch plan is missing jobs")?;
    anyhow::ensure!(
        jobs.len() == trials && required_usize(plan, "jobCount")? == trials,
        "scan-batch job count must equal trialsPlanned"
    );
    let mut job_ids = BTreeSet::new();
    let mut logical_ids = BTreeSet::new();
    for (index, job) in jobs.iter().enumerate() {
        validate_job(
            job,
            batch_id,
            index + 1,
            base_input,
            equivalence_key,
            &mut job_ids,
            &mut logical_ids,
        )?;
    }
    Ok(())
}

fn validate_job(
    job: &Value,
    batch_id: &str,
    trial: usize,
    base_input: &Value,
    equivalence_key: &str,
    job_ids: &mut BTreeSet<String>,
    logical_ids: &mut BTreeSet<String>,
) -> Result<()> {
    let job_id = required_string(job, "jobId")?;
    let logical_id = required_string(job, "logicalTrialId")?;
    anyhow::ensure!(job_ids.insert(job_id), "scan-batch job ids must be unique");
    anyhow::ensure!(
        logical_ids.insert(logical_id),
        "scan-batch logical trial ids must be unique"
    );
    let expected = scan_batch_job(batch_id, trial, base_input, equivalence_key);
    anyhow::ensure!(
        *job == expected,
        "scan-batch trial {trial} differs from immutable baseInput/provenance"
    );
    Ok(())
}

fn validate_worker_receipt(plan: &Value, trials: usize) -> Result<(usize, usize)> {
    let requested = required_usize(plan, "requestedWorkers")?;
    let effective = required_usize(plan, "effectiveWorkers")?;
    let receipt: ParallelSafetyResolution =
        serde_json::from_value(required_value(plan, "parallelSafety")?)
            .context("scan-batch plan has an invalid parallelSafety receipt")?;
    anyhow::ensure!(
        requested >= 1 && effective >= 1 && effective <= trials,
        "scan-batch worker counts are outside their logical-trial bounds"
    );
    anyhow::ensure!(
        receipt.requested_workers == requested
            && receipt.effective_workers == effective
            && plan.get("workers").and_then(Value::as_u64) == Some(effective as u64),
        "scan-batch frozen worker fields disagree"
    );
    Ok((requested, effective))
}

fn required_value(value: &Value, key: &str) -> Result<Value> {
    value
        .get(key)
        .cloned()
        .with_context(|| format!("scan-batch plan is missing {key}"))
}

fn required_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .with_context(|| format!("scan-batch plan is missing {key}"))
}

fn required_usize(value: &Value, key: &str) -> Result<usize> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|number| number as usize)
        .with_context(|| format!("scan-batch plan is missing {key}"))
}
