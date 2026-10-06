//! Typed campaign fold shared by `campaign:status` and the cockpit deck.
//!
//! One fold rule, one implementation: the dispatcher queue owns job
//! lifecycle truth when present; any job the queue has not touched is
//! `planned`. Everything here is read-only over `plan.json` + `queue.json`.

use super::{campaign_plan_path, campaign_queue_path, campaigns_dir, read_json_file};
use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

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
    pub attempts: u64,
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
    let plan = read_json_file(&campaign_plan_path(root, campaign_id))
        .with_context(|| format!("campaign {campaign_id:?} has no readable plan"))?;
    let queue_doc = load_queue_doc(root, campaign_id)?;
    let queue = queue_doc
        .get("jobs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let jobs = plan_job_rows(&plan)
        .map(|row| job_snapshot(root, row, &queue))
        .collect::<Vec<_>>();
    let total_cost_usd = jobs.iter().filter_map(|job| job.cost_usd).sum::<f64>() + 0.0;
    let provider_spend_unresolved = jobs.iter().any(|job| job.provider_spend_unresolved);
    Ok(CampaignSnapshot {
        campaign_id: campaign_id.to_string(),
        kind: plan.get("kind").and_then(Value::as_str).map(str::to_string),
        requested_workers: usize_field(&plan, "requestedWorkers"),
        effective_workers: usize_field(&plan, "effectiveWorkers"),
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

fn job_snapshot(root: &Path, row: &Value, queue: &Map<String, Value>) -> CampaignJobSnapshot {
    let job_id = string_field(row, "jobId").unwrap_or_default();
    let entry = queue.get(&job_id).cloned().unwrap_or(Value::Null);
    let run_id = string_field(&entry, "runId");
    CampaignJobSnapshot {
        findings: run_finding_count(root, run_id.as_deref()),
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
        exit_code: entry.get("exitCode").and_then(Value::as_i64),
        cost_usd: entry.get("costUsd").and_then(Value::as_f64),
        provider_spend_unresolved: entry
            .get("providerSpendUnresolved")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        run_id,
        reason: job_reason(root, row, &entry),
        job_id,
    }
}

fn job_reason(root: &Path, row: &Value, entry: &Value) -> Option<String> {
    string_field(entry, "reason").or_else(|| recorded_job_failure(root, row, entry))
}

fn recorded_job_failure(root: &Path, row: &Value, entry: &Value) -> Option<String> {
    let state = entry["state"].as_str()?;
    if !["failed", "partial", "interrupted", "parked"].contains(&state) {
        return None;
    }
    let run = crate::run_artifacts::load_run_summary_without_repair(root, entry["runId"].as_str()?)
        .ok()?;
    let tool = row["tool"].as_str()?;
    if run.tool.as_deref() != Some(tool)
        || !["failed", "partial", "canceled"].contains(&run.status.as_str())
    {
        return None;
    }
    run.error
        .map(|error| crate::run_artifacts::bounded_run_diagnostic_line(&error))
        .filter(|error| !error.is_empty())
}

/// Finding count from the child run's finalized metadata. Absent while the
/// run is still live (run.json carries no `findings` until completion) or
/// when the run directory was pruned.
fn run_finding_count(root: &Path, run_id: Option<&str>) -> Option<u64> {
    let (_, body) = crate::run_artifacts::read_run_artifact_text(root, run_id?, "run.json")
        .require("Run finding count")
        .ok()?;
    serde_json::from_str::<Value>(&body)
        .ok()?
        .get("findings")?
        .as_u64()
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn load_queue_doc(root: &Path, campaign_id: &str) -> Result<Value> {
    let path = campaign_queue_path(root, campaign_id);
    if !path.exists() {
        return Ok(Value::Null);
    }
    read_json_file(&path).with_context(|| format!("campaign {campaign_id:?} has no readable queue"))
}

#[cfg(test)]
mod tests;
