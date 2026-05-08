use super::prelude::*;
use super::*;

pub(crate) fn scan_result_or_report_ci_error(
    result: Result<serde_json::Value>,
    ci: bool,
    started: std::time::Instant,
    elapsed: std::time::Duration,
) -> Result<serde_json::Value> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            emit_scan_ci_error(ci, started, elapsed, &error);
            Err(error)
        }
    }
}

pub(crate) fn emit_scan_ci_error(
    ci: bool,
    started: std::time::Instant,
    elapsed: std::time::Duration,
    error: &anyhow::Error,
) {
    if ci {
        println!(
            "{}",
            ci_line(
                started,
                "phase",
                &format!("scanning → failed ({})", format_duration(elapsed))
            )
        );
        println!("{}", ci_line(started, "error", &error.to_string()));
        println!("{}", ci_line(started, "exit", "1"));
    }
}

pub(crate) fn emit_scan_output(
    workspace: &WorkspaceTarget,
    result: &serde_json::Value,
    json: bool,
    ci: bool,
    started: std::time::Instant,
    elapsed: std::time::Duration,
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

pub(crate) fn emit_scan_ci_success(
    result: &serde_json::Value,
    data: &serde_json::Value,
    started: std::time::Instant,
    elapsed: std::time::Duration,
) {
    println!(
        "{}",
        ci_line(
            started,
            "phase",
            &format!("scanning → done ({})", format_duration(elapsed))
        )
    );
    println!(
        "{}",
        ci_line(
            started,
            "summary",
            &format!(
                "{} finding(s) · ${:.4} · {}",
                scan_findings_count(data),
                scan_cost_usd(result),
                format_duration(elapsed)
            )
        )
    );
    println!("{}", ci_line(started, "exit", "0"));
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
