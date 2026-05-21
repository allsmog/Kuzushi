use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn write_missing_snapshot_marker(
    path: PathBuf,
    run_id: &str,
    status: &str,
    summary: &str,
) -> Result<()> {
    let marker = missing_snapshot(run_id, status, summary);
    if !marker_target_exists_as_file(&path)? || is_missing_snapshot_marker(&path, run_id, summary) {
        return write_json(path, marker);
    }
    Ok(())
}

pub(crate) fn write_empty_failures_marker(path: PathBuf, run_id: &str, status: &str) -> Result<()> {
    if failure_file_has_failures(&path) {
        return Ok(());
    }
    write_json(path, empty_failures(run_id, status))
}

pub(crate) fn write_missing_report_marker(
    path: PathBuf,
    run_id: &str,
    status: &str,
) -> Result<()> {
    let marker = missing_report(run_id, status);
    if !marker_target_exists_as_file(&path)? || is_missing_report_marker(&path, run_id) {
        return fs::write(&path, marker)
            .with_context(|| format!("Could not write {}", path.display()));
    }
    Ok(())
}

fn marker_target_exists_as_file(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => anyhow::bail!("Canonical marker target is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn missing_snapshot(run_id: &str, status: &str, summary: &str) -> Value {
    json!({
        "runId": run_id,
        "run_id": run_id,
        "status": "skipped",
        "runStatus": status,
        "summary": summary,
        "artifacts": [],
        "warnings": [summary],
        "errors": []
    })
}

fn empty_failures(run_id: &str, status: &str) -> Value {
    json!({
        "runId": run_id,
        "status": status,
        "failures": []
    })
}

fn missing_report(run_id: &str, status: &str) -> String {
    format!("# Kuzushi Run {run_id}\n\nStatus: {status}\n\nNo report was recorded for this run.\n")
}

fn is_missing_snapshot_marker(path: &Path, run_id: &str, summary: &str) -> bool {
    read_json(path)
        .as_ref()
        .is_some_and(|value| matches_missing_snapshot_marker(value, run_id, summary))
}

fn matches_missing_snapshot_marker(value: &Value, run_id: &str, summary: &str) -> bool {
    value.get("status").and_then(Value::as_str) == Some("skipped")
        && value.get("runId").and_then(Value::as_str) == Some(run_id)
        && value.get("summary").and_then(Value::as_str) == Some(summary)
        && value
            .get("artifacts")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn failure_file_has_failures(path: &Path) -> bool {
    read_json(path)
        .and_then(|value| value.get("failures").and_then(Value::as_array).cloned())
        .is_some_and(|failures| !failures.is_empty())
}

fn is_missing_report_marker(path: &Path, run_id: &str) -> bool {
    let Ok(body) = fs::read_to_string(path) else {
        return false;
    };
    body.contains(&format!("# Kuzushi Run {run_id}"))
        && body.contains("No report was recorded for this run.")
}

fn read_json(path: &Path) -> Option<Value> {
    let body = fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&body).ok()
}

fn write_json(path: PathBuf, value: Value) -> Result<()> {
    let body = format!("{}\n", serde_json::to_string_pretty(&value)?);
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}
