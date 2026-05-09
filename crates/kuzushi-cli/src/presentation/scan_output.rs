use super::scan_ci::{emit_scan_ci_error, emit_scan_ci_success};
use anyhow::Result;
use kuzushi_core::WorkspaceTarget;
use std::time::{Duration, Instant};

pub(crate) fn scan_result_or_report_ci_error(
    result: Result<serde_json::Value>,
    ci: bool,
    started: Instant,
    elapsed: Duration,
) -> Result<serde_json::Value> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            emit_scan_ci_error(ci, started, elapsed, &error);
            Err(error)
        }
    }
}

pub(crate) fn emit_scan_output(
    workspace: &WorkspaceTarget,
    result: &serde_json::Value,
    json: bool,
    ci: bool,
    started: Instant,
    elapsed: Duration,
) -> Result<()> {
    let data = scan_result_data(result);
    if ci {
        emit_scan_ci_success(result, &data, started, elapsed);
        return Ok(());
    }
    if json {
        println!("{}", scan_json_output(workspace, &data));
    } else if let Some(output) = result.get("output").and_then(serde_json::Value::as_str) {
        println!("{output}");
    }
    Ok(())
}

pub(crate) fn scan_result_data(result: &serde_json::Value) -> serde_json::Value {
    result
        .get("data")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}))
}

pub(crate) fn scan_json_output(
    workspace: &WorkspaceTarget,
    data: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "runId": data.get("runId").cloned(),
        "target": data.get("target").cloned(),
        "findingsCount": data.get("findingsCount").cloned(),
        "db": workspace.findings_db_path(),
        "mode": data.get("mode").cloned(),
        "whiteboxStatic": data.get("whiteboxStatic").cloned(),
        "triage": data.get("triage").cloned(),
    })
}

pub(crate) fn scan_findings_count(data: &serde_json::Value) -> u64 {
    data.get("findingsCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

pub(crate) fn scan_cost_usd(result: &serde_json::Value) -> f64 {
    result
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
}
