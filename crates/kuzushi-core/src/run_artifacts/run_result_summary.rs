use super::{
    load_run_summary, read_run_artifact_bytes, read_run_artifact_text, RunArtifact, RunArtifactRead,
};
use crate::module_result::{tool_result_status, ToolResultStatus};
use crate::run_lifecycle::{sha256_content_digest, ArtifactReference, RunItemId};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

const MAX_OUTPUT_LINES: usize = 12;
const MAX_MESSAGES: usize = 8;
const MAX_ARTIFACTS: usize = 16;
const MAX_LINE_CHARS: usize = 500;
const OPERATOR_OUTPUT_PREFIXES: &[&str] = &[
    "Status:",
    "Result:",
    "Threats:",
    "DFD:",
    "Findings:",
    "Cost:",
    "Saved:",
    "Artifact:",
];

/// Bounded semantic projection of one canonical `result.json`.
///
/// The full result artifact remains authoritative. This projection keeps the
/// fields needed by live Run Focus and durable phase receipts without making
/// presentation code reinterpret arbitrary module JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResultSummary {
    pub run_id: String,
    pub tool: String,
    pub status: String,
    pub summary: String,
    pub output_lines: Vec<String>,
    pub output_line_count: u64,
    pub warnings: Vec<String>,
    pub warning_count: u64,
    pub errors: Vec<String>,
    pub error_count: u64,
    pub artifacts: Vec<RunArtifact>,
    pub artifact_count: u64,
}

impl RunResultSummary {
    pub fn operator_output_preview(&self, limit: usize) -> Vec<&str> {
        if limit == 0 {
            return Vec::new();
        }
        let mut indices = Vec::new();
        let prioritized = prioritized_output_indices(&self.output_lines);
        for index in prioritized.chain(0..self.output_lines.len()) {
            if append_preview_index(&mut indices, index, limit) {
                break;
            }
        }
        indices
            .into_iter()
            .map(|index| self.output_lines[index].as_str())
            .collect()
    }
}

fn prioritized_output_indices(output_lines: &[String]) -> impl Iterator<Item = usize> + '_ {
    OPERATOR_OUTPUT_PREFIXES.iter().filter_map(|prefix| {
        output_lines
            .iter()
            .position(|line| line.starts_with(prefix))
    })
}

fn append_preview_index(indices: &mut Vec<usize>, index: usize, limit: usize) -> bool {
    if !indices.contains(&index) {
        indices.push(index);
    }
    indices.len() == limit
}

pub fn load_run_result_summary(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Option<RunResultSummary>> {
    let target = target.as_ref();
    let body = match read_run_artifact_text(target, run_id, "result.json") {
        RunArtifactRead::Missing { .. } => return Ok(None),
        read => read.require("Tool result")?.1,
    };
    let raw = serde_json::from_str::<Value>(&body)
        .with_context(|| format!("Tool result for run {run_id} is malformed"))?;
    Ok(Some(project_run_result(target, run_id, &raw)))
}

/// Load a typed run result only through its exact call-correlated reference.
///
/// This is intentionally distinct from the legacy filename loader above:
/// typed consumers must supply the reference carried by `ToolCallFinished`.
pub fn load_correlated_run_result_summary(
    target: impl AsRef<Path>,
    run_id: &str,
    producing_item_id: RunItemId,
    reference: &ArtifactReference,
) -> Result<RunResultSummary> {
    let result =
        load_correlated_run_result_value(target.as_ref(), run_id, producing_item_id, reference)?;
    Ok(project_run_result(target.as_ref(), run_id, &result))
}

pub(crate) fn load_correlated_run_result_value(
    target: &Path,
    run_id: &str,
    producing_item_id: RunItemId,
    reference: &ArtifactReference,
) -> Result<Value> {
    anyhow::ensure!(
        reference.producing_item_id == producing_item_id,
        "result artifact producer identity does not match its call"
    );
    let (_, bytes) = read_run_artifact_bytes(target, run_id, reference.path.as_str())
        .require("Correlated tool result")?;
    validate_reference_bytes(reference, &bytes)?;
    let body = std::str::from_utf8(&bytes).context("Correlated tool result is not UTF-8")?;
    validate_reference_lines(reference, body)?;
    let raw = serde_json::from_str::<Value>(body)
        .with_context(|| format!("Correlated tool result for run {run_id} is malformed"))?;
    Ok(raw)
}

fn validate_reference_bytes(reference: &ArtifactReference, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        reference.byte_count == bytes.len() as u64,
        "correlated result size does not match its reference"
    );
    let digest = sha256_content_digest(bytes);
    anyhow::ensure!(
        reference.digest.as_str() == digest,
        "correlated result digest does not match its reference"
    );
    Ok(())
}

fn validate_reference_lines(reference: &ArtifactReference, body: &str) -> Result<()> {
    let Some(expected) = reference.line_count else {
        return Ok(());
    };
    anyhow::ensure!(
        expected == body.lines().count() as u64,
        "correlated result line count does not match its reference"
    );
    Ok(())
}

fn project_run_result(target: &Path, run_id: &str, result: &Value) -> RunResultSummary {
    let status = persisted_result_status(result).to_string();
    let output = output_lines(result);
    let warnings = message_lines(result, "warnings");
    let errors = message_lines(result, "errors");
    let artifacts = result_artifacts(target, run_id, result);
    RunResultSummary {
        run_id: safe_bounded_line(run_id),
        tool: safe_bounded_line(&result_tool_name(target, run_id, result)),
        summary: result_summary(result, &status),
        status,
        output_lines: output.values,
        output_line_count: output.total,
        warnings: warnings.values,
        warning_count: warnings.total,
        errors: errors.values,
        error_count: errors.total,
        artifacts: artifacts.values,
        artifact_count: artifacts.total,
    }
}

struct BoundedValues<T> {
    values: Vec<T>,
    total: u64,
}

fn result_tool_name(target: &Path, run_id: &str, result: &Value) -> String {
    load_run_summary(target, run_id)
        .ok()
        .and_then(|summary| summary.tool)
        .or_else(|| value_string(result.pointer("/data/tool")))
        .unwrap_or_else(|| "tool".to_string())
}

fn result_summary(result: &Value, status: &str) -> String {
    condensed_value_string(result.get("summary"))
        .filter(|summary| !summary.is_empty())
        .unwrap_or_else(|| format!("tool result {status}"))
}

fn output_lines(result: &Value) -> BoundedValues<String> {
    collect_bounded(
        result
            .get("output")
            .and_then(Value::as_str)
            .into_iter()
            .flat_map(str::lines)
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(safe_bounded_line),
        MAX_OUTPUT_LINES,
    )
}

fn message_lines(result: &Value, field: &str) -> BoundedValues<String> {
    let declared = result
        .get(field)
        .and_then(Value::as_array)
        .map_or(0, |values| values.len() as u64);
    let mut bounded = collect_bounded(
        result
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| condensed_value_string(Some(value)))
            .filter(|message| !message.is_empty()),
        MAX_MESSAGES,
    );
    bounded.total = declared;
    bounded
}

fn result_artifacts(target: &Path, run_id: &str, result: &Value) -> BoundedValues<RunArtifact> {
    let declared = result
        .get("artifacts")
        .and_then(Value::as_array)
        .map_or(0, |values| values.len() as u64);
    let artifacts = result
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|artifact| serde_json::from_value::<RunArtifact>(artifact.clone()).ok())
        .collect::<Vec<_>>();
    let artifacts =
        super::run_artifact::normalize_run_artifact_identities(target, run_id, artifacts);
    let mut bounded = collect_bounded(
        artifacts.into_iter().map(safe_artifact_projection),
        MAX_ARTIFACTS,
    );
    bounded.total = declared;
    bounded
}

fn collect_bounded<T>(values: impl Iterator<Item = T>, maximum: usize) -> BoundedValues<T> {
    let mut bounded = Vec::with_capacity(maximum);
    let mut total = 0_u64;
    for value in values {
        total = total.saturating_add(1);
        if bounded.len() < maximum {
            bounded.push(value);
        }
    }
    let values = bounded;
    BoundedValues { values, total }
}

fn safe_artifact_projection(mut artifact: RunArtifact) -> RunArtifact {
    artifact.label = safe_bounded_line(&artifact.label);
    artifact.path = safe_bounded_line(&artifact.path);
    artifact.kind = safe_bounded_line(&artifact.kind);
    artifact
}

fn value_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .map(safe_bounded_line)
}

fn condensed_value_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(condensed_bounded_line)
}

/// One-line projection of possibly multi-line producer text: lines are
/// trimmed and joined with " · " before escaping, so a condensed summary or
/// message never shows a literal `\n` where the producer meant a line break.
fn condensed_bounded_line(value: &str) -> String {
    let joined = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" · ");
    safe_bounded_line(&joined)
}

pub(crate) fn safe_bounded_line(value: &str) -> String {
    let redacted = crate::session_transcript::redaction::redact_text(value);
    let safe = escape_control_characters(&redacted);
    if safe.chars().count() <= MAX_LINE_CHARS {
        return safe;
    }
    let mut bounded = safe.chars().take(MAX_LINE_CHARS - 1).collect::<String>();
    bounded.push('…');
    bounded
}

fn escape_control_characters(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            safe.extend(character.escape_default());
        } else {
            safe.push(character);
        }
    }
    safe
}

fn result_status_label(status: ToolResultStatus) -> &'static str {
    match status {
        ToolResultStatus::Completed => "completed",
        ToolResultStatus::Partial => "partial",
        ToolResultStatus::Skipped => "skipped",
        ToolResultStatus::Failed => "failed",
    }
}

fn persisted_result_status(result: &Value) -> &str {
    match result.get("status").and_then(Value::as_str) {
        Some(status)
            if matches!(
                status,
                "completed"
                    | "partial"
                    | "skipped"
                    | "blocked"
                    | "failed"
                    | "canceled"
                    | "interrupted"
            ) =>
        {
            status
        }
        _ => result_status_label(tool_result_status(result)),
    }
}

#[cfg(test)]
#[path = "run_result_summary/tests.rs"]
mod tests;
