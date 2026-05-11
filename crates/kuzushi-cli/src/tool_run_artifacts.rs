use kuzushi_core::{
    append_run_trace_step, next_run_trace_step_number, write_run_artifact_json, write_run_summary,
    RunSummary, RunTraceStep,
};
use std::path::Path;

pub(crate) fn finish_cli_tool_run(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
) {
    let result_artifact =
        write_run_artifact_json(target, run_id, "result.json", "result", output).ok();
    let mut summary = RunSummary::running(
        run_id.to_string(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(run_output_findings_count(output))
    .with_cost(run_output_cost_usd(output));
    if let Some(artifact) = result_artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(
            next_run_trace_step_number(target, run_id),
            "done",
            format!("{tool} complete"),
        )
        .with_tool_name(tool)
        .with_cost_usd(run_output_cost_usd(output)),
    );
    let _ = write_run_summary(target, &summary);
}

pub(crate) fn fail_cli_tool_run(target: &Path, run_id: &str, tool: &str, error: &str) {
    let summary = RunSummary::running(
        run_id.to_string(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .failed(error.to_string());
    let _ = append_run_trace_step(
        target,
        run_id,
        &RunTraceStep::new(
            next_run_trace_step_number(target, run_id),
            "refused",
            format!("{tool} failed"),
        )
        .with_tool_name(tool)
        .with_severity("danger"),
    );
    let _ = write_run_summary(target, &summary);
}

pub(crate) fn run_output_findings_count(output: &serde_json::Value) -> Option<u64> {
    output
        .pointer("/data/findingsCount")
        .or_else(|| output.get("findingsCount"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            output
                .pointer("/data/findings")
                .and_then(serde_json::Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}

pub(crate) fn run_output_cost_usd(output: &serde_json::Value) -> Option<f64> {
    output
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            output
                .pointer("/data/costUsd")
                .and_then(serde_json::Value::as_f64)
        })
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}
