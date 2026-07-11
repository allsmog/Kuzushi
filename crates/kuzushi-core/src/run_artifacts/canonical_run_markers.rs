use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn write_empty_failures_marker(
    target: &Path,
    run_id: &str,
    leaf: &str,
    status: &str,
) -> Result<()> {
    let path = super::checked_run_artifact_path(target, run_id, leaf)?;
    if failure_file_has_failures(target, run_id, leaf)? {
        return Ok(());
    }
    write_json(target, path, empty_failures(run_id, status))
}

pub(crate) fn write_missing_report_marker(
    target: &Path,
    run_id: &str,
    leaf: &str,
    status: &str,
) -> Result<()> {
    let path = super::checked_run_artifact_path(target, run_id, leaf)?;
    let marker = missing_report(run_id, status);
    let existing = read_marker_text(target, run_id, leaf, "Canonical report marker")?;
    if existing
        .as_deref()
        .is_none_or(|body| is_missing_report_marker(body, run_id))
    {
        return write_marker_text(target, &path, &marker);
    }
    Ok(())
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

fn failure_file_has_failures(target: &Path, run_id: &str, leaf: &str) -> Result<bool> {
    Ok(read_json(target, run_id, leaf)?
        .and_then(|value| value.get("failures").and_then(Value::as_array).cloned())
        .is_some_and(|failures| !failures.is_empty()))
}

fn is_missing_report_marker(body: &str, run_id: &str) -> bool {
    body.contains(&format!("# Kuzushi Run {run_id}"))
        && body.contains("No report was recorded for this run.")
}

fn read_json(target: &Path, run_id: &str, leaf: &str) -> Result<Option<Value>> {
    let Some(body) = read_marker_text(target, run_id, leaf, "Canonical failures marker")?
    else {
        return Ok(None);
    };
    serde_json::from_str::<Value>(&body)
        .map(Some)
        .context("Could not parse canonical failures marker")
}

fn write_json(target: &Path, path: PathBuf, value: Value) -> Result<()> {
    let body = format!("{}\n", serde_json::to_string_pretty(&value)?);
    write_marker_text(target, &path, &body)
}

fn read_marker_text(
    target: &Path,
    run_id: &str,
    leaf: &str,
    label: &str,
) -> Result<Option<String>> {
    match super::read_run_artifact_text(target, run_id, leaf) {
        super::RunArtifactRead::Ready { value, .. } => Ok(Some(value)),
        super::RunArtifactRead::Missing { .. } => Ok(None),
        other => Err(other.require(label).unwrap_err()),
    }
}

fn write_marker_text(target: &Path, path: &Path, body: &str) -> Result<()> {
    let root = fs::canonicalize(target)
        .with_context(|| format!("Could not resolve marker target {}", target.display()))?;
    let relative = path
        .strip_prefix(target)
        .or_else(|_| path.strip_prefix(&root))
        .context("Canonical marker path escaped the workspace")?;
    crate::workspace::write_workspace_state_file(target, relative, body.as_bytes())
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(())
}
