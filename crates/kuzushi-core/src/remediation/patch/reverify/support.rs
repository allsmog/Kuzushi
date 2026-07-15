use super::super::hash_optional_file;
use crate::findings::{Finding, PatchLifecycleRecord, PatchLifecycleState, PatchStatus};
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::path::{Component, Path};

mod detector_binding;
use detector_binding::originating_detector_binding;

pub(super) const APPLICATION_ID: &str = "applicationId";
pub(super) const DETECTOR_TOOL: &str = "detectorTool";
pub(super) const DETECTOR_RUN_ID: &str = "detectorRunId";
pub(super) const DETECTOR_INPUT: &str = "detectorInput";
pub(super) const COMPARISON_UNAVAILABLE: &str = "comparisonUnavailable";

pub(super) fn load_record(
    store: &crate::findings::FindingStore,
    application_id: &str,
    target: &Path,
) -> Result<PatchLifecycleRecord> {
    let record = store
        .get_patch_lifecycle(application_id)?
        .with_context(|| format!("patch application {application_id:?} was not found"))?;
    ensure_record_target(&record, target)?;
    Ok(record)
}

pub(super) fn bind_originating_detector(
    object: &mut Map<String, Value>,
    store: &crate::findings::FindingStore,
    target: &Path,
    record: &PatchLifecycleRecord,
) {
    for key in [
        DETECTOR_TOOL,
        DETECTOR_RUN_ID,
        DETECTOR_INPUT,
        COMPARISON_UNAVAILABLE,
    ] {
        object.remove(key);
    }
    match originating_detector_binding(store, target, record) {
        Ok(binding) => insert_detector_binding(object, binding),
        Err(error) => {
            object.insert(COMPARISON_UNAVAILABLE.to_string(), json!(error.to_string()));
        }
    }
}

#[derive(Debug)]
struct DetectorBinding {
    tool: String,
    run_id: String,
    input: Value,
}

fn insert_detector_binding(object: &mut Map<String, Value>, binding: DetectorBinding) {
    object.insert(DETECTOR_TOOL.to_string(), json!(binding.tool));
    object.insert(DETECTOR_RUN_ID.to_string(), json!(binding.run_id));
    object.insert(DETECTOR_INPUT.to_string(), binding.input);
}

pub(super) fn changed_touched_path(
    target: &Path,
    record: &PatchLifecycleRecord,
) -> Result<Option<String>> {
    for file in &record.touched_files {
        ensure_relative_touched_path(&file.path)?;
        let current = hash_optional_file(target, Path::new(&file.path))?;
        if current != file.after_hash {
            return Ok(Some(file.path.clone()));
        }
    }
    Ok(None)
}

fn ensure_relative_touched_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    anyhow::ensure!(!path.is_absolute(), "stored touched path must be relative");
    anyhow::ensure!(
        path.components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
        "stored touched path escapes the target"
    );
    Ok(())
}

pub(super) fn rediscovery_outcome(
    store: &crate::findings::FindingStore,
    ctx: &ToolExecutionContext<'_>,
    record: &PatchLifecycleRecord,
    deterministic: bool,
) -> Result<PatchLifecycleState> {
    let run_id = ctx
        .run_id()
        .context("re-verification run has no durable run id for comparison")?;
    let original = store.get_finding_by_fingerprint(&record.fingerprint)?;
    let candidates = store.list_findings_for_scan_id(&run_id)?;
    if candidates
        .iter()
        .any(|candidate| same_finding(original.as_ref(), candidate, record))
    {
        return Ok(PatchLifecycleState::StillVulnerable);
    }
    Ok(absence_outcome(deterministic))
}

fn absence_outcome(deterministic: bool) -> PatchLifecycleState {
    if deterministic {
        PatchLifecycleState::Verified
    } else {
        PatchLifecycleState::NotRediscovered
    }
}

fn same_finding(
    original: Option<&Finding>,
    candidate: &Finding,
    record: &PatchLifecycleRecord,
) -> bool {
    candidate.fingerprint == record.fingerprint
        || original
            .and_then(|finding| finding.identity_id.as_ref())
            .zip(candidate.identity_id.as_ref())
            .is_some_and(|(left, right)| left == right)
}

pub(super) fn promote_patch_result(
    store: &crate::findings::FindingStore,
    record: &PatchLifecycleRecord,
    outcome: PatchLifecycleState,
) -> Result<()> {
    let status = match outcome {
        PatchLifecycleState::Verified => PatchStatus::Verified,
        PatchLifecycleState::StillVulnerable => PatchStatus::StillVulnerable,
        _ => return Ok(()),
    };
    let mut result = store
        .get_patch_results_for_finding(&record.fingerprint)?
        .into_iter()
        .find(|result| result.patch_run_id == record.patch_run_id)
        .context("the originating patch result is unavailable")?;
    result.status = status;
    result.updated_at = Some(crate::findings::now_isoish());
    store.insert_patch_result(&result)
}

pub(super) fn record_state(
    store: &crate::findings::FindingStore,
    record: &mut PatchLifecycleRecord,
    state: PatchLifecycleState,
    detail: Option<String>,
) -> Result<()> {
    record.state = state;
    record.detail = detail;
    record.updated_at = crate::findings::now_isoish();
    store.insert_patch_lifecycle_record(record)
}

pub(super) fn interrupted_state(
    ctx: &ToolExecutionContext<'_>,
    error: &anyhow::Error,
) -> PatchLifecycleState {
    let detail = error.to_string().to_ascii_lowercase();
    if ctx.cancellation.is_some_and(|token| token.is_cancelled())
        || detail.contains("interrupt")
        || detail.contains("process loss")
    {
        return PatchLifecycleState::Interrupted;
    }
    PatchLifecycleState::Failed
}

fn ensure_record_target(record: &PatchLifecycleRecord, target: &Path) -> Result<()> {
    let recorded = std::fs::canonicalize(&record.target)
        .with_context(|| format!("recorded patch target {:?} is unavailable", record.target))?;
    let active = std::fs::canonicalize(target)
        .with_context(|| format!("active patch target {} is unavailable", target.display()))?;
    anyhow::ensure!(
        recorded == active,
        "patch application belongs to another target"
    );
    Ok(())
}

pub(super) fn required_string<'a>(input: &'a Value, key: &str) -> Result<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("patch:reverify requires {key}"))
}

pub(super) fn detector_failure_detail(output: &Value) -> String {
    let detail = output
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("; ")
        .trim()
        .to_string();
    if detail.is_empty() {
        "originating detector returned a failure result".to_string()
    } else {
        detail
    }
}

pub(super) fn outcome_detail(state: PatchLifecycleState) -> String {
    match state {
        PatchLifecycleState::Verified => "deterministic detector completed without rediscovery",
        PatchLifecycleState::StillVulnerable => "originating detector rediscovered the finding",
        PatchLifecycleState::NotRediscovered => {
            "nondeterministic detector completed without rediscovery"
        }
        _ => "re-verification completed",
    }
    .to_string()
}

pub(super) fn completed_reverify_output(record: &PatchLifecycleRecord, detector: &str) -> Value {
    crate::module_result::completed_output_result(
        format!("patch:reverify {}", record.state.as_str()),
        record.detail.clone().unwrap_or_default(),
        json!({
            "applicationId": record.application_id,
            "detector": detector,
            "outcome": record.state.as_str(),
            "reverifyRunId": record.reverify_run_id,
        }),
    )
}

pub(super) fn failed_reverify_output(record: &PatchLifecycleRecord, detail: &str) -> Value {
    crate::module_result::failed_output_result(
        format!("patch:reverify {}", record.state.as_str()),
        detail,
        json!({
            "applicationId": record.application_id,
            "outcome": record.state.as_str(),
            "reverifyRunId": record.reverify_run_id,
        }),
    )
}

#[cfg(test)]
mod tests;
