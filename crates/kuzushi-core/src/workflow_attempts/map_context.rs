//! Authenticated context from the runs that actually produced a Map attempt.
use crate::capabilities::threat_model::{
    load_exact_threat_model, ThreatModelRef, ThreatModelSelection,
};
use crate::run_lifecycle::{CallProjection, ProjectionHealth};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct MapRunContext {
    pub run_id: String,
    pub model_ref: Option<ThreatModelRef>,
    pub allowance_ref: Option<crate::allowance::AllowanceReferenceV1>,
    pub document: Value,
}

/// Never substitute target-global context for missing or damaged run evidence.
pub fn load_map_run_context(target: &Path, run_refs: &[String]) -> Result<Option<MapRunContext>> {
    for run_id in run_refs.iter().rev() {
        if let Some(context) = context_from_run(target, run_id)? {
            return Ok(Some(context));
        }
    }
    Ok(None)
}

pub(crate) fn accepted_map_context_selection(target: &Path) -> Result<ThreatModelSelection> {
    let Some(record) = accepted_map_attempt(target)? else {
        return Ok(ThreatModelSelection::Active);
    };
    let reference = load_map_run_context(target, &record.completed.run_refs)?
        .and_then(|context| context.model_ref);
    Ok(reference.map_or(ThreatModelSelection::None, ThreatModelSelection::Revision))
}

pub(crate) fn accepted_map_run_context(target: &Path) -> Result<Option<MapRunContext>> {
    let Some(record) = accepted_map_attempt(target)? else {
        return Ok(None);
    };
    load_map_run_context(target, &record.completed.run_refs)
}

/// Historical spending remains relevant when explicitly preparing a new Map.
/// This never permits historical context to satisfy current-source discovery.
pub(crate) fn selected_map_history_run_context(target: &Path) -> Result<Option<MapRunContext>> {
    let ledger = healthy_map_history(target)?;
    let snapshot = super::PhaseTargetSnapshot::capture(target);
    let Some(record) =
        ledger.latest_selected_history_for_target(crate::WorkflowPhase::Map, &snapshot)
    else {
        return Ok(None);
    };
    load_map_run_context(target, &record.completed.run_refs)
}

fn healthy_map_history(target: &Path) -> Result<super::PhaseAttemptLedger> {
    let recovered = super::load_phase_attempt_ledger_recovering(target)?;
    anyhow::ensure!(
        !recovered.is_degraded(),
        "Map history is damaged; inspect it before preparing a study"
    );
    Ok(recovered.ledger)
}

fn accepted_map_attempt(target: &Path) -> Result<Option<super::PhaseAttemptRecord>> {
    let ledger = healthy_map_history(target)?;
    let snapshot = super::PhaseTargetSnapshot::capture(target);
    let Some(record) = ledger.selected_for(crate::WorkflowPhase::Map, &snapshot) else {
        anyhow::ensure!(
            ledger.latest_selected_history_for_target(crate::WorkflowPhase::Map, &snapshot).is_none(),
            "Accepted Map belongs to earlier source content; accept a current Map or explicitly select study context"
        );
        return Ok(None);
    };
    Ok(Some(record.clone()))
}

fn context_from_run(target: &Path, run_id: &str) -> Result<Option<MapRunContext>> {
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    anyhow::ensure!(
        projection.health == ProjectionHealth::Healthy,
        "Map run {run_id} has a degraded evidence stream"
    );
    for call_id in projection.call_order.iter().rev() {
        let call = projection
            .calls
            .get(call_id)
            .context("Map run call is missing")?;
        if let Some(context) = context_from_call(target, run_id, call)? {
            return Ok(Some(context));
        }
    }
    Ok(None)
}

fn context_from_call(
    target: &Path,
    run_id: &str,
    call: &CallProjection,
) -> Result<Option<MapRunContext>> {
    let Some(reference) = &call.result_artifact else {
        return Ok(None);
    };
    let result = crate::run_artifacts::load_correlated_run_result_value(
        target,
        run_id,
        call.item_id,
        reference,
    )
    .with_context(|| format!("Map evidence for run {run_id} cannot be authenticated"))?;
    context_from_result(target, run_id, &result)
}

fn context_from_result(
    target: &Path,
    run_id: &str,
    result: &Value,
) -> Result<Option<MapRunContext>> {
    let model_ref = result
        .pointer("/data/modelRef")
        .filter(|value| !value.is_null());
    if let Some(reference) = model_ref {
        return exact_context_from_result(target, run_id, reference, result).map(Some);
    }
    let Some(document) = result
        .pointer("/data/document")
        .or_else(|| result.pointer("/structured/document"))
        .filter(|document| document.get("dfd").is_some())
        .cloned()
    else {
        return Ok(None);
    };
    Ok(Some(MapRunContext {
        run_id: run_id.into(),
        model_ref: None,
        allowance_ref: result_allowance_reference(result)?,
        document,
    }))
}

fn exact_context_from_result(
    target: &Path,
    run_id: &str,
    reference: &Value,
    result: &Value,
) -> Result<MapRunContext> {
    let reference: ThreatModelRef = serde_json::from_value(reference.clone())
        .context("Map run has an invalid immutable context reference")?;
    let context = load_exact_threat_model(target, &reference)?;
    if let Some(document) = result.pointer("/data/document") {
        anyhow::ensure!(
            *document == context,
            "Map run document disagrees with its immutable context"
        );
    }
    Ok(MapRunContext {
        run_id: run_id.into(),
        model_ref: Some(reference),
        allowance_ref: result_allowance_reference(result)?,
        document: context,
    })
}

fn result_allowance_reference(
    result: &Value,
) -> Result<Option<crate::allowance::AllowanceReferenceV1>> {
    let Some(reference) = result.get("allowanceRef") else {
        return Ok(None);
    };
    let reference: crate::allowance::AllowanceReferenceV1 =
        serde_json::from_value(reference.clone())
            .context("Map result has invalid investigation accounting provenance")?;
    reference.validate()?;
    Ok(Some(reference))
}

#[cfg(test)]
mod tests;
