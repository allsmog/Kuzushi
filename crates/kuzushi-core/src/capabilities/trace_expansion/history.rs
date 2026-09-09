use super::TraceExpansionResult;
use crate::run_artifacts::{list_run_summaries, load_correlated_run_result_value, RunSummary};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

/// A complete recorded outcome, including expansions that added no steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedTraceExpansion {
    pub run_id: String,
    pub result: TraceExpansionResult,
    pub source: TraceExpansionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceExpansionSource {
    Current,
    Changed,
    Unrecorded,
    Unverified,
}

/// Recover the newest completed or partial expansion for this finding.
/// The canonical result must agree with its terminal receipt and digest.
/// Failed runs do not replace a completed outcome; corrupt results are errors.
pub fn load_latest_trace_expansion(
    target: &Path,
    fingerprint: &str,
) -> Result<Option<RecordedTraceExpansion>> {
    for summary in list_run_summaries(target)?
        .iter()
        .filter(|run| is_expansion(run))
    {
        let value = checked_result(target, summary)?;
        let result = result_contract(&value)?;
        if result.finding_fingerprint == fingerprint {
            return Ok(Some(RecordedTraceExpansion {
                run_id: summary.run_id.clone(),
                result,
                source: recorded_source(target, &value),
            }));
        }
    }
    Ok(None)
}

fn is_expansion(summary: &RunSummary) -> bool {
    summary.tool.as_deref() == Some("trace:expand")
        && matches!(summary.status.as_str(), "completed" | "partial")
}

fn checked_result(target: &Path, summary: &RunSummary) -> Result<Value> {
    let read = crate::run_lifecycle::load_run_projection(target, &summary.run_id)?;
    anyhow::ensure!(
        matches!(
            read.projection.health,
            crate::run_lifecycle::ProjectionHealth::Healthy
        ),
        "Trace expansion lifecycle is degraded"
    );
    let reference = exact_result_reference(&read.projection)?;
    let value = load_correlated_run_result_value(
        target,
        &summary.run_id,
        reference.producing_item_id,
        reference,
    )?;
    anyhow::ensure!(
        value["status"].as_str() == Some(summary.status.as_str()),
        "Trace expansion status disagrees with its run summary"
    );
    anyhow::ensure!(
        value.pointer("/data/tool").and_then(Value::as_str) == Some("trace:expand"),
        "Trace expansion result names a different tool"
    );
    Ok(value)
}

fn exact_result_reference(
    projection: &crate::run_lifecycle::RunProjection,
) -> Result<&crate::run_lifecycle::ArtifactReference> {
    let references = projection
        .calls
        .values()
        .filter_map(|call| call.result_artifact.as_ref())
        .filter(|reference| reference.path.as_str() == "result.json")
        .collect::<Vec<_>>();
    match references.as_slice() {
        [reference] => Ok(*reference),
        _ => anyhow::bail!("Trace expansion requires one call-correlated result receipt"),
    }
}

fn result_contract(value: &Value) -> Result<TraceExpansionResult> {
    let data = value
        .get("data")
        .context("Trace expansion has no result data")?;
    // Cost, source and append receipts belong to the envelope, not the model contract.
    super::contract::parse_trace_expansion_result(json!({
        "version": data["version"],
        "findingFingerprint": data["findingFingerprint"],
        "steps": data["steps"],
        "openQuestions": data.get("openQuestions").cloned().unwrap_or(json!([])),
        "evidenceDeltas": data.get("evidenceDeltas").cloned().unwrap_or(json!([])),
    }))
}

fn recorded_source(target: &Path, value: &Value) -> TraceExpansionSource {
    let Some(tree_hash) = value.pointer("/data/treeHash").and_then(Value::as_str) else {
        return TraceExpansionSource::Unrecorded;
    };
    match crate::incremental_index::current_workspace_tree_hash(target) {
        Ok(current) if current == tree_hash => TraceExpansionSource::Current,
        Ok(_) => TraceExpansionSource::Changed,
        Err(_) => TraceExpansionSource::Unverified,
    }
}

#[cfg(test)]
mod tests;
