use super::*;
use super::canonical_run_files::record_canonical_snapshot_artifacts;
use super::output_declared_artifacts::record_output_declared_artifacts;
use super::tool_run_failure_result::failed_tool_result_with_context;
use super::tool_run_record_events::{
    append_done_trace, append_failed_trace, append_started_event, append_started_trace,
    append_tool_event,
};

#[derive(Debug, Clone, Copy)]
pub struct ToolRunRecord<'a> {
    pub target: &'a Path,
    pub run_id: &'a str,
    pub kind: &'a str,
    pub tool: &'a str,
}

impl<'a> ToolRunRecord<'a> {
    pub fn new(target: &'a Path, run_id: &'a str, kind: &'a str, tool: &'a str) -> Self {
        Self {
            target,
            run_id,
            kind,
            tool,
        }
    }
}

pub fn record_tool_run_started(record: ToolRunRecord<'_>, input: &Value) {
    let mut summary = RunSummary::running(
        record.run_id.to_string(),
        record.kind,
        Some(record.tool.to_string()),
        record.target.display().to_string(),
    )
    .with_process_id(std::process::id());
    let input_artifact =
        write_run_artifact_json(record.target, record.run_id, "input.json", "input", input).ok();
    if let Some(artifact) = input_artifact.clone() {
        summary = summary.with_artifact(artifact);
    }
    append_started_event(record, input_artifact);
    append_started_trace(record);
    let _ = write_run_summary(record.target, &summary);
}

pub fn record_tool_run_complete(record: ToolRunRecord<'_>, output: &Value) {
    let status = tool_run_output_status(output);
    let mut artifacts = existing_run_artifacts(record);
    artifacts.extend(record_output_declared_artifacts(
        record.target,
        record.run_id,
        output,
    ));
    artifacts.extend(record_canonical_snapshot_artifacts(
        record.target,
        record.run_id,
        output,
    ));
    let output = result_output_for_status(record, status, output, &mut artifacts);
    artifacts.extend(result_artifact(record, &output));
    let summary = completed_summary(record, &output, artifacts);
    let summary = apply_output_status(status, summary);
    append_tool_event(record, status, "tool result recorded");
    append_done_trace(record, status, tool_run_output_cost_usd(&output));
    let _ = write_run_summary(record.target, &summary);
}

pub fn record_tool_run_failed(record: ToolRunRecord<'_>, error: &str) {
    let mut artifacts = existing_run_artifacts(record);
    let mut summary = failed_summary(record, error, &artifacts);
    if let Ok(failure_artifact) = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        "failed",
        error,
        &artifacts,
    ) {
        artifacts.push(failure_artifact.clone());
        summary = summary.with_artifact(failure_artifact);
    }
    let output =
        failed_tool_result_with_context(record.target, record.run_id, record.tool, error, &artifacts);
    if let Some(result_artifact) = result_artifact(record, &output) {
        summary = summary.with_artifact(result_artifact);
    }
    append_tool_event(record, "failed", "tool failed");
    append_failed_trace(record);
    let _ = write_run_summary(record.target, &summary);
}

pub fn tool_run_output_cost_usd(output: &Value) -> Option<f64> {
    output
        .get("costUsd")
        .and_then(Value::as_f64)
        .or_else(|| output.pointer("/data/costUsd").and_then(Value::as_f64))
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

pub fn tool_run_output_findings_count(output: &Value) -> Option<u64> {
    output
        .pointer("/data/findingsCount")
        .or_else(|| output.get("findingsCount"))
        .and_then(Value::as_u64)
        .or_else(|| {
            output
                .pointer("/data/findings")
                .and_then(Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}

fn result_artifact(record: ToolRunRecord<'_>, output: &Value) -> Option<RunArtifact> {
    write_run_artifact_json(
        record.target,
        record.run_id,
        "result.json",
        "result",
        output,
    )
    .ok()
}

fn completed_summary(
    record: ToolRunRecord<'_>,
    output: &Value,
    artifacts: Vec<RunArtifact>,
) -> RunSummary {
    artifacts.into_iter().fold(
        RunSummary::running(
            record.run_id.to_string(),
            record.kind,
            Some(record.tool.to_string()),
            record.target.display().to_string(),
        )
        .complete()
        .with_findings(tool_run_output_findings_count(output))
        .with_cost(tool_run_output_cost_usd(output)),
        RunSummary::with_artifact,
    )
}

fn result_output_for_status(
    record: ToolRunRecord<'_>,
    status: &str,
    output: &Value,
    artifacts: &mut Vec<RunArtifact>,
) -> Value {
    if failure_like_status(status) {
        attach_failure_artifact(record, status, output, artifacts);
        return output_with_run_fallback_context(record.target, record.run_id, output.clone());
    }
    output.clone()
}

fn apply_output_status(status: &str, mut summary: RunSummary) -> RunSummary {
    if failure_like_status(status) {
        summary.status = status.to_string();
    }
    if status == "skipped" {
        summary.status = "skipped".to_string();
    }
    summary
}

fn failed_summary(record: ToolRunRecord<'_>, error: &str, artifacts: &[RunArtifact]) -> RunSummary {
    artifacts.iter().cloned().fold(
        RunSummary::running(
            record.run_id.to_string(),
            record.kind,
            Some(record.tool.to_string()),
            record.target.display().to_string(),
        )
        .failed(error.to_string()),
        RunSummary::with_artifact,
    )
}

fn tool_run_output_status(output: &Value) -> &'static str {
    output
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| output.pointer("/data/status").and_then(Value::as_str))
        .map(canonical_tool_output_status)
        .unwrap_or("completed")
}

fn canonical_tool_output_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "complete" | "completed" | "ok" | "success" => "completed",
        "partial" => "partial",
        "skipped" | "skip" => "skipped",
        "failed" | "error" => "failed",
        _ => "completed",
    }
}

fn failure_like_status(status: &str) -> bool {
    matches!(status, "partial" | "failed")
}

fn existing_run_artifacts(record: ToolRunRecord<'_>) -> Vec<RunArtifact> {
    load_run_summary(record.target, record.run_id)
        .map(|summary| summary.artifacts)
        .unwrap_or_default()
}

fn attach_failure_artifact(
    record: ToolRunRecord<'_>,
    status: &str,
    output: &Value,
    artifacts: &mut Vec<RunArtifact>,
) {
    let error = tool_run_output_error(output);
    if let Ok(artifact) = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        status,
        &error,
        artifacts,
    ) {
        artifacts.push(artifact);
    }
}

fn tool_run_output_error(output: &Value) -> String {
    output
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_str)
        .or_else(|| output.get("error").and_then(Value::as_str))
        .or_else(|| output.get("summary").and_then(Value::as_str))
        .unwrap_or("module returned a non-completed status")
        .to_string()
}
