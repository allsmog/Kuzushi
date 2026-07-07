use super::*;
use super::canonical_run_files::record_canonical_snapshot_artifacts;
use super::output_declared_artifacts::record_output_declared_artifacts;
use super::tool_run_failure_result::failed_tool_result_with_context;
use super::tool_run_record_events::{
    append_done_trace, append_failed_trace, append_started_event, append_started_trace,
    append_tool_event,
};
use crate::artifact_contract::{tool_input_artifact_spec, tool_result_artifact_spec};
use crate::module_result::normalize_module_result;

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
    record_tool_run_started_with_metadata(record, input, None, None);
}

pub fn record_tool_run_started_with_metadata(
    record: ToolRunRecord<'_>,
    input: &Value,
    model: Option<String>,
    config_hash: Option<String>,
) {
    record_tool_run_started_with_reproducibility(record, input, model, config_hash, Vec::new());
}

pub fn record_tool_run_started_with_reproducibility(
    record: ToolRunRecord<'_>,
    input: &Value,
    model: Option<String>,
    config_hash: Option<String>,
    loaded_modules: Vec<String>,
) {
    let mut summary = RunSummary::running(
        record.run_id.to_string(),
        record.kind,
        Some(record.tool.to_string()),
        record.target.display().to_string(),
    )
    .with_process_id(std::process::id())
    .with_model(model)
    .with_config_hash(config_hash)
    .with_loaded_modules(loaded_modules);
    let input_artifact = input_artifact(record, input);
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

fn tool_run_output_model(output: &Value) -> Option<String> {
    output
        .get("model")
        .or_else(|| output.pointer("/data/model"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn result_artifact(record: ToolRunRecord<'_>, output: &Value) -> Option<RunArtifact> {
    let spec = tool_result_artifact_spec("result.json")
        .expect("tool result artifact must be in shared spec");
    write_run_artifact_json(
        record.target,
        record.run_id,
        spec.leaf,
        spec.label,
        output,
    )
    .ok()
}

fn input_artifact(record: ToolRunRecord<'_>, input: &Value) -> Option<RunArtifact> {
    let spec =
        tool_input_artifact_spec("input.json").expect("tool input artifact must be in shared spec");
    write_run_artifact_json(record.target, record.run_id, spec.leaf, spec.label, input).ok()
}

fn completed_summary(
    record: ToolRunRecord<'_>,
    output: &Value,
    artifacts: Vec<RunArtifact>,
) -> RunSummary {
    let seed = summary_seed(record)
        .complete()
        .with_findings(tool_run_output_findings_count(output))
        .with_cost(tool_run_output_cost_usd(output));
    let seed = with_output_model(seed, output);
    artifacts
        .into_iter()
        .fold(seed, RunSummary::with_artifact)
}

fn summary_seed(record: ToolRunRecord<'_>) -> RunSummary {
    let seed = RunSummary::running(
        record.run_id.to_string(),
        record.kind,
        Some(record.tool.to_string()),
        record.target.display().to_string(),
    );
    match load_run_summary(record.target, record.run_id) {
        Ok(existing) => summary_seed_from_existing(seed, &existing),
        Err(_) => seed,
    }
}

fn summary_seed_from_existing(mut seed: RunSummary, existing: &RunSummary) -> RunSummary {
    seed.started_at_unix = existing.started_at_unix;
    seed.with_reproducibility_from(existing)
}

fn with_output_model(summary: RunSummary, output: &Value) -> RunSummary {
    let Some(model) = tool_run_output_model(output) else {
        return summary;
    };
    summary.with_model(Some(model))
}

fn result_output_for_status(
    record: ToolRunRecord<'_>,
    status: &str,
    output: &Value,
    artifacts: &mut Vec<RunArtifact>,
) -> Value {
    if failure_like_status(status) {
        attach_failure_artifact(record, status, output, artifacts);
        return normalize_module_result(output_with_run_fallback_context(
            record.target,
            record.run_id,
            output.clone(),
        ));
    }
    normalize_module_result(output.clone())
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
        summary_seed(record).failed(error.to_string()),
        RunSummary::with_artifact,
    )
}

fn tool_run_output_status(output: &Value) -> &'static str {
    if output.get("ok").and_then(Value::as_bool) == Some(false) {
        return "failed";
    }
    output
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| output.pointer("/data/status").and_then(Value::as_str))
        .map(canonical_tool_output_status)
        .unwrap_or("completed")
}

fn canonical_tool_output_status(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "completed" => "completed",
        "partial" => "partial",
        "skipped" => "skipped",
        "failed" => "failed",
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
