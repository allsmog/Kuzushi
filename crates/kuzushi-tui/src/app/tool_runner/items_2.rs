use super::prelude::*;
use super::*;

pub(crate) fn extract_cost_usd(result: &serde_json::Value) -> Option<f64> {
    result
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            result
                .pointer("/data/costUsd")
                .and_then(serde_json::Value::as_f64)
        })
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

pub(crate) fn record_tool_run_complete(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    result: &serde_json::Value,
) {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return;
    };
    let artifact = write_run_artifact_json(target, run_id, "result.json", "result", result).ok();
    let mut summary = RunSummary::running(
        run_id.to_string(),
        "tool",
        Some(tool_name.to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(extract_findings_count(result))
    .with_cost(extract_cost_usd(result));
    if let Some(artifact) = artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool_name} complete"))
            .with_cost_usd(extract_cost_usd(result)),
    );
    let _ = write_run_summary(target, &summary);
}

pub(crate) fn record_tool_run_failed(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    tool_name: &str,
    error: &str,
) {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return;
    };
    let summary = RunSummary::running(
        run_id.to_string(),
        "tool",
        Some(tool_name.to_string()),
        target.display().to_string(),
    )
    .failed(error.to_string());
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(2, "tool", format!("{tool_name} failed")),
    );
    let _ = write_run_summary(target, &summary);
}

pub(crate) fn extract_findings_count(value: &serde_json::Value) -> Option<u64> {
    value
        .pointer("/data/findingsCount")
        .or_else(|| value.get("findingsCount"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            value
                .pointer("/data/findings")
                .and_then(serde_json::Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}
