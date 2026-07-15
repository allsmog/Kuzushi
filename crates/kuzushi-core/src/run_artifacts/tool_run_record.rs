use super::canonical_run_files::record_report_artifacts;
use super::output_declared_artifacts::record_output_declared_artifacts;
use super::tool_run_failure_result::failed_tool_result_with_context;
use super::tool_run_record_events::{
    append_done_trace, append_failed_trace, append_started_event, append_started_trace,
    append_tool_event,
};
use super::*;
use crate::artifact_contract::{tool_input_artifact_spec, tool_result_artifact_spec};
use crate::module_result::{normalize_module_result, tool_result_status, ToolResultStatus};
use serde_json::json;

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
    let _ = try_record_tool_run_started_with_reproducibility(
        record,
        input,
        model,
        config_hash,
        loaded_modules,
    );
}

pub fn try_record_tool_run_started_with_reproducibility(
    record: ToolRunRecord<'_>,
    input: &Value,
    model: Option<String>,
    config_hash: Option<String>,
    loaded_modules: Vec<String>,
) -> Result<()> {
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
    let input_artifact = input_artifact(record, input)?;
    summary = summary.with_artifact(input_artifact.clone());
    write_run_summary(record.target, &summary)?;
    append_started_event(record, Some(input_artifact))?;
    append_started_trace(record)?;
    Ok(())
}

pub fn record_tool_run_complete(record: ToolRunRecord<'_>, output: &Value) {
    let _ = try_record_tool_run_complete(record, output);
}

pub fn try_record_tool_run_complete(record: ToolRunRecord<'_>, output: &Value) -> Result<()> {
    let status = tool_result_status_label(tool_result_status(output));
    let terminal_digest = terminal_result_digest(status, &normalize_module_result(output.clone()));
    let _guard = super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id)?;
    validate_terminalization(record, status, &terminal_digest)?;
    let mut artifacts = existing_run_artifacts(record)?;
    let output_artifacts =
        record_output_declared_artifacts(record.target, record.run_id, output, &artifacts)?;
    artifacts.extend(output_artifacts);
    artifacts.extend(record_report_artifacts(
        record.target,
        record.run_id,
        output,
    )?);
    let output = result_output_for_status(record, status, output, &mut artifacts)?;
    artifacts.push(result_artifact(record, &output)?);
    let summary = completed_summary(record, &output, artifacts)?;
    let summary = apply_output_status(status, summary, &output)
        .with_terminal_result_sha256(Some(terminal_digest));
    append_tool_event(record, status, "tool result recorded")?;
    append_done_trace(
        record,
        status,
        tool_run_output_cost_report(&output)?.exact_usd(),
    )?;
    write_run_summary(record.target, &summary)?;
    Ok(())
}

pub fn record_tool_run_failed(record: ToolRunRecord<'_>, error: &str) {
    let _ = try_record_tool_run_failed(record, error);
}

pub fn try_record_tool_run_failed(record: ToolRunRecord<'_>, error: &str) -> Result<()> {
    let terminal_digest = terminal_result_digest("failed", &json!({ "error": error }));
    let _guard = super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id)?;
    validate_terminalization(record, "failed", &terminal_digest)?;
    let mut artifacts = existing_run_artifacts(record)?;
    let mut summary = failed_summary(record, error, &artifacts)?;
    let failure_artifact = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        "failed",
        error,
        &artifacts,
    )?;
    artifacts.push(failure_artifact.clone());
    summary = summary.with_artifact(failure_artifact);
    let output = failed_tool_result_with_context(
        record.target,
        record.run_id,
        record.tool,
        error,
        &artifacts,
    );
    summary = summary
        .with_artifact(result_artifact(record, &output)?)
        .with_terminal_result_sha256(Some(terminal_digest));
    append_tool_event(record, "failed", "tool failed")?;
    append_failed_trace(record)?;
    write_run_summary(record.target, &summary)?;
    Ok(())
}

pub fn record_tool_run_canceled(record: ToolRunRecord<'_>, reason: &str) {
    let _ = try_record_tool_run_canceled(record, reason);
}

pub fn try_record_tool_run_canceled(record: ToolRunRecord<'_>, reason: &str) -> Result<()> {
    try_record_interrupted_tool_run(record, "canceled", reason)
}

pub fn record_tool_run_interrupted(record: ToolRunRecord<'_>, reason: &str) {
    let _ = try_record_tool_run_interrupted(record, reason);
}

pub fn try_record_tool_run_interrupted(record: ToolRunRecord<'_>, reason: &str) -> Result<()> {
    try_record_interrupted_tool_run(record, "interrupted", reason)
}

pub fn record_tool_run_refused(record: ToolRunRecord<'_>, reason: &str) {
    let _ = try_record_tool_run_refused(record, reason);
}

pub fn try_record_tool_run_refused(record: ToolRunRecord<'_>, reason: &str) -> Result<()> {
    let terminal_digest = terminal_result_digest("skipped", &json!({ "reason": reason }));
    let _guard = super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id)?;
    validate_terminalization(record, "skipped", &terminal_digest)?;
    let artifacts = existing_run_artifacts(record)?;
    let summary = artifacts
        .into_iter()
        .fold(
            summary_seed(record)?.skipped(reason),
            RunSummary::with_artifact,
        )
        .with_terminal_result_sha256(Some(terminal_digest));
    append_tool_event(record, "skipped", reason)?;
    append_done_trace(record, "skipped", None)?;
    write_run_summary(record.target, &summary)?;
    Ok(())
}

fn try_record_interrupted_tool_run(
    record: ToolRunRecord<'_>,
    status: &str,
    reason: &str,
) -> Result<()> {
    let terminal_digest = terminal_result_digest(status, &json!({ "reason": reason }));
    let _guard = super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id)?;
    validate_terminalization(record, status, &terminal_digest)?;
    let artifacts = existing_run_artifacts(record)?;
    let seed = summary_seed(record)?;
    let summary = if status == "canceled" {
        seed.canceled(reason)
    } else {
        seed.interrupted(reason)
    }
    .with_cost_report(super::trace_cost::trace_cost_report(
        record.target,
        record.run_id,
    )?);
    let summary = artifacts
        .into_iter()
        .fold(summary, RunSummary::with_artifact)
        .with_terminal_result_sha256(Some(terminal_digest));
    let message = format!("tool {status}: {reason}");
    append_tool_event(record, status, &message)?;
    append_done_trace(record, status, None)?;
    write_run_summary(record.target, &summary)?;
    Ok(())
}

pub fn tool_run_output_cost_usd(output: &Value) -> Option<f64> {
    tool_run_output_cost_report(output)
        .ok()
        .and_then(crate::runtime::RuntimeCostReport::exact_usd)
}

pub fn tool_run_output_findings_count(output: &Value) -> Option<u64> {
    output
        .pointer("/data/findingsCount")
        .or_else(|| output.get("findingsCount"))
        .or_else(|| output.pointer("/data/count"))
        .or_else(|| output.pointer("/data/totals/findings"))
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

fn result_artifact(record: ToolRunRecord<'_>, output: &Value) -> Result<RunArtifact> {
    let spec = tool_result_artifact_spec("result.json")
        .expect("tool result artifact must be in shared spec");
    write_run_artifact_json(record.target, record.run_id, spec.leaf, spec.label, output)
}

fn input_artifact(record: ToolRunRecord<'_>, input: &Value) -> Result<RunArtifact> {
    let spec =
        tool_input_artifact_spec("input.json").expect("tool input artifact must be in shared spec");
    write_run_artifact_json(record.target, record.run_id, spec.leaf, spec.label, input)
}

fn completed_summary(
    record: ToolRunRecord<'_>,
    output: &Value,
    artifacts: Vec<RunArtifact>,
) -> Result<RunSummary> {
    let seed = summary_seed(record)?;
    let output_cost = tool_run_output_cost_report(output)?;
    let trace_cost = super::trace_cost::trace_cost_report(record.target, record.run_id)?;
    let terminal_cost = super::trace_cost::reconcile_terminal_cost_reports(
        output_cost,
        trace_cost,
        "tool terminal",
    )?;
    let cost = super::trace_cost::reconcile_terminal_cost_reports(
        seed.checked_cost_report()?,
        terminal_cost,
        "tool terminal seed",
    )?;
    let seed = seed
        .complete()
        .with_findings(tool_run_output_findings_count(output))
        .with_cost_report(cost);
    let seed = with_output_model(seed, output);
    Ok(artifacts.into_iter().fold(seed, RunSummary::with_artifact))
}

fn summary_seed(record: ToolRunRecord<'_>) -> Result<RunSummary> {
    let seed = RunSummary::running(
        record.run_id.to_string(),
        record.kind,
        Some(record.tool.to_string()),
        record.target.display().to_string(),
    );
    let existing =
        super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
            .with_context(|| {
                format!(
                    "could not load {} before terminalizing run {}",
                    run_artifact_path(record.target, record.run_id, "run.json").display(),
                    record.run_id,
                )
            })?;
    Ok(summary_seed_from_existing(seed, &existing))
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
) -> Result<Value> {
    if failure_like_status(status) {
        attach_failure_artifact(record, status, output, artifacts)?;
        return Ok(normalize_module_result(output_with_run_fallback_context(
            record.target,
            record.run_id,
            output.clone(),
        )));
    }
    Ok(normalize_module_result(output.clone()))
}

fn apply_output_status(status: &str, mut summary: RunSummary, output: &Value) -> RunSummary {
    if failure_like_status(status) {
        summary.status = status.to_string();
        summary.error = Some(tool_run_output_error(output));
    }
    if status == "skipped" {
        summary.status = "skipped".to_string();
        summary.error = Some(tool_run_output_error(output));
    }
    summary
}

fn failed_summary(
    record: ToolRunRecord<'_>,
    error: &str,
    artifacts: &[RunArtifact],
) -> Result<RunSummary> {
    let cost = super::trace_cost::trace_cost_report(record.target, record.run_id)?;
    Ok(artifacts.iter().cloned().fold(
        summary_seed(record)?
            .failed(error.to_string())
            .with_cost_report(cost),
        RunSummary::with_artifact,
    ))
}

fn tool_result_status_label(status: ToolResultStatus) -> &'static str {
    match status {
        ToolResultStatus::Completed => "completed",
        ToolResultStatus::Partial => "partial",
        ToolResultStatus::Skipped => "skipped",
        ToolResultStatus::Failed => "failed",
    }
}

fn failure_like_status(status: &str) -> bool {
    matches!(status, "partial" | "failed")
}

fn validate_terminalization(
    record: ToolRunRecord<'_>,
    status: &str,
    terminal_digest: &str,
) -> Result<()> {
    let summary =
        super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
            .with_context(|| {
                format!(
                    "could not verify existing terminal state for run {} from {}",
                    record.run_id,
                    run_artifact_path(record.target, record.run_id, "run.json").display(),
                )
            })?;
    if !is_terminal_run_status(&summary.status) {
        return Ok(());
    }
    ensure_same_terminal_status(record, status, &summary)?;
    ensure_same_terminal_content(record, terminal_digest, &summary)
}

fn ensure_same_terminal_status(
    record: ToolRunRecord<'_>,
    status: &str,
    summary: &RunSummary,
) -> Result<()> {
    if summary.status != status {
        anyhow::bail!(
            "run {} is already terminal with status {}; refusing to rewrite it as {status}",
            record.run_id,
            summary.status
        )
    }
    Ok(())
}

fn ensure_same_terminal_content(
    record: ToolRunRecord<'_>,
    terminal_digest: &str,
    summary: &RunSummary,
) -> Result<()> {
    let Some(existing_digest) = summary.terminal_result_sha256.as_deref() else {
        anyhow::bail!(
            "run {} is already terminal but has no terminal result digest; refusing an unverifiable retry",
            record.run_id
        )
    };
    if existing_digest != terminal_digest {
        anyhow::bail!(
            "run {} is already terminal with different result content; refusing a divergent retry",
            record.run_id
        )
    }
    Ok(())
}

fn is_terminal_run_status(status: &str) -> bool {
    matches!(
        status,
        "completed" | "partial" | "skipped" | "failed" | "canceled" | "interrupted"
    )
}

fn existing_run_artifacts(record: ToolRunRecord<'_>) -> Result<Vec<RunArtifact>> {
    super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
        .map(|summary| summary.artifacts)
        .with_context(|| format!("could not load artifacts for run {}", record.run_id))
}

pub(crate) fn terminal_result_digest(status: &str, result: &Value) -> String {
    let bytes = serde_json::to_vec(&json!({
        "status": status,
        "result": result,
    }))
    .expect("terminal intent is always JSON serializable");
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(&bytes)
    )
}

fn attach_failure_artifact(
    record: ToolRunRecord<'_>,
    status: &str,
    output: &Value,
    artifacts: &mut Vec<RunArtifact>,
) -> Result<()> {
    let error = tool_run_output_error(output);
    let artifact = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        status,
        &error,
        artifacts,
    )?;
    artifacts.push(artifact);
    Ok(())
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
