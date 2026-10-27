//! Typed campaign fold shared by `campaign:status` and the cockpit deck.
//!
//! One fold rule, one implementation: the dispatcher queue owns job
//! lifecycle truth when present; any job the queue has not touched is
//! `planned`. Everything here is read-only over `plan.json` + `queue.json`.

use super::{campaign_plan_path, campaign_queue_path, campaigns_dir};
use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
mod labels;
mod progress;
mod reader;
pub use progress::load_approved_scan_snapshot;
pub(super) use reader::SnapshotReader;

#[derive(Debug, Clone, PartialEq)]
pub struct CampaignSnapshot {
    pub campaign_id: String,
    /// Plan-kind discriminator. Dedicated scan batches use `scan-batch`;
    /// legacy campaign plans may omit the field.
    pub kind: Option<String>,
    /// Dedicated batch plans freeze dispatcher width at compile time.
    pub requested_workers: Option<usize>,
    pub effective_workers: Option<usize>,
    pub parallel_safety_reason: Option<String>,
    pub tool: Option<String>,
    pub created_at_ms: Option<u64>,
    pub paused_until_ms: Option<u64>,
    /// USD cap recorded by the most recent dispatcher launch; `None` means
    /// the last dispatcher ran unlimited (or none has run yet).
    pub budget_usd: Option<f64>,
    /// Per-job USD ceiling recorded by the most recent dispatcher launch;
    /// running jobs that cross it are killed and parked `over-budget`.
    pub job_budget_usd: Option<f64>,
    /// True when the plan skipped shard × source cells the coverage fold
    /// already reported covered (`campaign:plan` with `fillGaps`).
    pub fill_gaps: bool,
    /// How many covered cells the gap-fill plan skipped.
    pub skipped_covered_cells: Option<u64>,
    pub total_cost_usd: f64,
    /// The total is only a lower bound when any child could not report its
    /// complete provider charge.
    pub provider_spend_unresolved: bool,
    pub jobs: Vec<CampaignJobSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CampaignJobSnapshot {
    pub job_id: String,
    /// Human case and pass label from this recorded plan, never current scope names.
    pub display_label: Option<String>,
    pub tool: Option<String>,
    pub shard: Option<String>,
    pub threat_id: Option<String>,
    pub threat_title: Option<String>,
    /// Threat-model document stem the job's threat came from (the coverage
    /// matrix's column axis).
    pub threat_source: Option<String>,
    pub priority: i64,
    pub prompt_path: Option<String>,
    pub input: Value,
    pub state: String,
    /// Current retry-ladder count, retained for compatibility. Resume may reset it.
    pub attempts: u64,
    /// Lifetime dispatched attempts. Missing or contradictory legacy counters are unknown.
    pub dispatches: Option<u64>,
    pub exit_code: Option<i64>,
    pub cost_usd: Option<f64>,
    pub provider_spend_unresolved: bool,
    pub run_id: Option<String>,
    pub reason: Option<String>,
    /// Finding count from the job's run artifact (`runs/<runId>/run.json`);
    /// present once the child run finalized its metadata.
    pub findings: Option<u64>,
}

impl CampaignSnapshot {
    pub fn state_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for job in &self.jobs {
            *counts.entry(job.state.clone()).or_insert(0) += 1;
        }
        counts
    }
}

/// Sorted ids of every campaign directory in the workspace.
pub fn campaign_ids(root: &Path) -> Result<Vec<String>> {
    let dir = campaigns_dir(root);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries =
        std::fs::read_dir(&dir).with_context(|| format!("Could not read {}", dir.display()))?;
    let mut ids = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

pub fn load_campaign_snapshot(root: &Path, campaign_id: &str) -> Result<CampaignSnapshot> {
    SnapshotReader::new(root, &|| false).load(campaign_id, true)
}

fn snapshot_from_documents(
    root: &Path,
    campaign_id: &str,
    plan: &Value,
    queue_doc: &Value,
) -> Result<CampaignSnapshot> {
    let mut reader = SnapshotReader::new(root, &|| false);
    fold_documents(
        campaign_id,
        plan,
        queue_doc,
        &mut |id| reader.run(id),
        &|| false,
    )
}

pub(super) fn fold_documents(
    campaign_id: &str,
    plan: &Value,
    queue_doc: &Value,
    read_run: &mut dyn FnMut(&str) -> Option<Value>,
    cancelled: &dyn Fn() -> bool,
) -> Result<CampaignSnapshot> {
    let queue = queue_doc
        .get("jobs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let jobs = fold_jobs(plan, &queue, read_run, cancelled)?;
    let total_cost_usd = jobs.iter().filter_map(|job| job.cost_usd).sum::<f64>() + 0.0;
    let provider_spend_unresolved = jobs.iter().any(|job| job.provider_spend_unresolved);
    Ok(CampaignSnapshot {
        campaign_id: campaign_id.to_string(),
        kind: plan.get("kind").and_then(Value::as_str).map(str::to_string),
        requested_workers: usize_field(plan, "requestedWorkers"),
        effective_workers: usize_field(plan, "effectiveWorkers"),
        parallel_safety_reason: plan
            .get("parallelSafety")
            .and_then(|value| string_field(value, "clampReason")),
        tool: plan.get("tool").and_then(Value::as_str).map(str::to_string),
        created_at_ms: plan.get("createdAtMs").and_then(Value::as_u64),
        paused_until_ms: queue_doc.get("pausedUntilMs").and_then(Value::as_u64),
        budget_usd: queue_doc.get("budgetUsd").and_then(Value::as_f64),
        job_budget_usd: queue_doc.get("jobBudgetUsd").and_then(Value::as_f64),
        fill_gaps: plan
            .get("fillGaps")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        skipped_covered_cells: plan.get("skippedCoveredCells").and_then(Value::as_u64),
        total_cost_usd,
        provider_spend_unresolved,
        jobs,
    })
}

fn fold_jobs(
    plan: &Value,
    queue: &Map<String, Value>,
    read_run: &mut dyn FnMut(&str) -> Option<Value>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<CampaignJobSnapshot>> {
    plan_job_rows(plan)
        .map(|row| {
            anyhow::ensure!(!cancelled(), "Investigation history loading was canceled");
            let entry = queue.get(row["jobId"].as_str().unwrap_or_default());
            let run = entry
                .and_then(|row| row["runId"].as_str())
                .and_then(&mut *read_run);
            Ok(job_snapshot_with_run(plan, row, queue, run.as_ref()))
        })
        .collect()
}

fn usize_field(value: &Value, key: &str) -> Option<usize> {
    usize::try_from(value.get(key)?.as_u64()?).ok()
}

fn plan_job_rows(plan: &Value) -> impl Iterator<Item = &Value> {
    plan.get("jobs")
        .and_then(Value::as_array)
        .map(|jobs| jobs.iter())
        .into_iter()
        .flatten()
}

#[cfg(test)]
fn job_snapshot(
    root: &Path,
    plan: &Value,
    row: &Value,
    queue: &Map<String, Value>,
) -> CampaignJobSnapshot {
    let mut reader = SnapshotReader::new(root, &|| false);
    let entry = queue.get(row["jobId"].as_str().unwrap_or_default());
    let run = entry
        .and_then(|row| row["runId"].as_str())
        .and_then(|id| reader.run(id));
    job_snapshot_with_run(plan, row, queue, run.as_ref())
}

fn job_snapshot_with_run(
    plan: &Value,
    row: &Value,
    queue: &Map<String, Value>,
    run: Option<&Value>,
) -> CampaignJobSnapshot {
    let job_id = string_field(row, "jobId").unwrap_or_default();
    let entry = queue.get(&job_id).cloned().unwrap_or(Value::Null);
    let run_id = string_field(&entry, "runId");
    CampaignJobSnapshot {
        display_label: labels::job_label(plan, row),
        findings: run.and_then(|run| run["findings"].as_u64()),
        tool: string_field(row, "tool"),
        shard: string_field(row, "shard"),
        threat_id: string_field(row, "threatId"),
        threat_title: string_field(row, "threatTitle"),
        threat_source: string_field(row, "threatSource"),
        priority: row.get("priority").and_then(Value::as_i64).unwrap_or(0),
        prompt_path: string_field(row, "promptPath"),
        input: row.get("input").cloned().unwrap_or(Value::Null),
        state: string_field(&entry, "state").unwrap_or_else(|| "planned".to_string()),
        attempts: entry.get("attempts").and_then(Value::as_u64).unwrap_or(0),
        dispatches: recorded_dispatches(&entry),
        exit_code: entry.get("exitCode").and_then(Value::as_i64),
        cost_usd: entry.get("costUsd").and_then(Value::as_f64),
        provider_spend_unresolved: entry
            .get("providerSpendUnresolved")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        run_id,
        reason: job_reason(row, &entry, run),
        job_id,
    }
}

fn recorded_dispatches(entry: &Value) -> Option<u64> {
    if entry.is_null() {
        return Some(0);
    }
    let total = entry.get("dispatches")?.as_u64()?;
    let current = entry.get("attempts").and_then(Value::as_u64).unwrap_or(0);
    let history = entry
        .get("attemptRuns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("runId").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>()
        .len() as u64;
    (total >= current.max(history)).then_some(total)
}

fn job_reason(row: &Value, entry: &Value, run: Option<&Value>) -> Option<String> {
    string_field(entry, "reason")
        .or_else(|| recorded_job_failure(row, entry, run?))
        .map(|reason| crate::run_artifacts::bounded_run_diagnostic_line(&reason))
}

fn recorded_job_failure(row: &Value, entry: &Value, run: &Value) -> Option<String> {
    let state = entry["state"].as_str()?;
    if !["failed", "partial", "interrupted", "parked"].contains(&state) {
        return None;
    }
    let tool = row["tool"].as_str()?;
    if run["tool"].as_str() != Some(tool)
        || !["failed", "partial", "canceled"].contains(&run["status"].as_str()?)
    {
        return None;
    }
    string_field(run, "error")
        .map(|error| crate::run_artifacts::bounded_run_diagnostic_line(&error))
        .filter(|error| !error.is_empty())
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests;
