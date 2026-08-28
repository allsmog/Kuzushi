use super::BatchTrialReport;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

mod receipts;

pub(super) use receipts::validate_batch_trial_receipts;

pub(super) fn trial_reports(plan: &Value, queue: Option<&Value>) -> Vec<BatchTrialReport> {
    plan.get("jobs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, row)| trial_report(index, row, queue))
        .collect()
}

fn trial_report(index: usize, row: &Value, queue: Option<&Value>) -> BatchTrialReport {
    let job_id = row
        .get("jobId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let state = queue.and_then(|doc| doc.pointer(&format!("/jobs/{job_id}")));
    let run_id = state_field(state, "runId");
    BatchTrialReport {
        trial: row
            .get("trial")
            .and_then(Value::as_u64)
            .unwrap_or((index + 1) as u64) as usize,
        job_id,
        state: state_field(state, "state").unwrap_or_else(|| "planned".to_string()),
        attempts: state
            .and_then(|value| value.get("attempts"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        attempt_run_ids: attempt_run_ids(state, run_id.as_deref()),
        run_id,
        finding_run_ids: Vec::new(),
        failure_reason: state_field(state, "reason"),
    }
}

fn attempt_run_ids(state: Option<&Value>, current: Option<&str>) -> Vec<String> {
    let mut run_ids = state
        .and_then(|value| value.get("attemptRuns"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|attempt| attempt.get("runId").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if let Some(current) = current {
        run_ids.insert(current.to_string());
    }
    run_ids.into_iter().collect()
}

fn state_field(value: Option<&Value>, key: &str) -> Option<String> {
    value?
        .get(key)?
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

pub(super) fn hydrate_finding_run_ids(root: &Path, trials: &mut [BatchTrialReport]) {
    for trial in trials.iter_mut().filter(|trial| trial.state == "completed") {
        trial.finding_run_ids = trial
            .attempt_run_ids
            .iter()
            .flat_map(|run_id| finding_run_ids(root, run_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
}

fn finding_run_ids(root: &Path, outer_run_id: &str) -> Vec<String> {
    let mut run_ids = BTreeSet::from([outer_run_id.to_string()]);
    if let Ok(outcome) =
        crate::run_artifacts::load_persisted_run_terminal_outcome(root, outer_run_id)
    {
        collect_result_run_ids(&outcome.result, &mut run_ids);
    }
    run_ids.into_iter().collect()
}

fn collect_result_run_ids(result: &Value, run_ids: &mut BTreeSet<String>) {
    if let Some(run_id) = result.pointer("/data/runId").and_then(Value::as_str) {
        insert_run_id(run_ids, run_id);
    }
    if let Some(children) = result.pointer("/data/runIds") {
        collect_run_ids(children, run_ids);
    }
}

fn collect_run_ids(value: &Value, run_ids: &mut BTreeSet<String>) {
    match value {
        Value::String(run_id) => insert_run_id(run_ids, run_id),
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_run_ids(value, run_ids)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_run_ids(value, run_ids)),
        _ => {}
    }
}

fn insert_run_id(run_ids: &mut BTreeSet<String>, run_id: &str) {
    let run_id = run_id.trim();
    if !run_id.is_empty() {
        run_ids.insert(run_id.to_string());
    }
}

pub(super) fn read_batch_document(root: &Path, batch_id: &str, file: &str) -> Result<Value> {
    let path = batch_file(root, batch_id, file);
    let body =
        std::fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&body).with_context(|| format!("{} is malformed JSON", path.display()))
}

pub(super) fn read_optional_batch_document(
    root: &Path,
    batch_id: &str,
    file: &str,
) -> Result<Option<Value>> {
    let path = batch_file(root, batch_id, file);
    match std::fs::read(&path) {
        Ok(body) => serde_json::from_slice(&body)
            .with_context(|| format!("{} is malformed JSON", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("could not read {}", path.display())),
    }
}

fn batch_file(root: &Path, batch_id: &str, file: &str) -> PathBuf {
    crate::capabilities::campaign::campaign_dir(root, batch_id).join(file)
}

pub(super) fn required_string(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .with_context(|| format!("scan-batch plan is missing {key}"))
}
