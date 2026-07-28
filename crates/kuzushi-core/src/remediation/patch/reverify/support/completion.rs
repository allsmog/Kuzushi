use super::super::ReverifyRequest;
use super::{
    changed_touched_path, completed_reverify_output, detector_failure_detail,
    failed_reverify_output, interrupted_state, outcome_detail, record_state,
};
use crate::capabilities::patch_reverification::{
    active_touched_hashes, empirical_detector_state, persist_receipt,
};
use crate::content_store::ObjectRef;
use crate::findings::{
    PatchDetectorReplayOutcome, PatchLifecycleState, PatchReverificationReceipt,
};
use crate::modules::ToolExecutionContext;
use anyhow::Result;
use serde_json::Value;

pub(crate) fn record_dispatch_error(
    request: &mut ReverifyRequest<'_>,
    mut receipt: Option<PatchReverificationReceipt>,
    ctx: &ToolExecutionContext<'_>,
    error: anyhow::Error,
) -> Result<Value> {
    let mut state = interrupted_state(ctx, &error);
    let mut detail = error.to_string();
    if let Some(receipt) = receipt.as_mut() {
        receipt.detector_outcome = PatchDetectorReplayOutcome::Failed;
        return finish_with_receipt(
            request.cloned(),
            state,
            detail,
            receipt.clone(),
            "unavailable",
        );
    }
    if let Some(path) = changed_touched_path(request.target, &request.record)? {
        state = PatchLifecycleState::ChangedSinceApply;
        detail = format!("{path} changed during detector replay");
    }
    record_state(
        request.store,
        &mut request.record,
        state,
        Some(detail.clone()),
    )?;
    Ok(failed_reverify_output(&request.record, &detail))
}

pub(crate) fn finish_detector_output(
    request: ReverifyRequest<'_>,
    detector: &str,
    output: Value,
    receipt: Option<PatchReverificationReceipt>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    if crate::module_result::tool_result_status(&output).is_failure_like() {
        return finish_detector_failure(request, detector, &output, receipt);
    }
    let outcome = super::rediscovery_outcome(request.store, ctx, &request.record)?;
    if let Some(receipt) = receipt {
        return finish_empirical_detector(request, detector, outcome, receipt);
    }
    finish_detector_without_receipt(request, detector, outcome)
}

fn finish_detector_failure(
    mut request: ReverifyRequest<'_>,
    detector: &str,
    output: &Value,
    mut receipt: Option<PatchReverificationReceipt>,
) -> Result<Value> {
    let mut state = PatchLifecycleState::Failed;
    let mut detail = detector_failure_detail(output);
    if let Some(receipt) = receipt.as_mut() {
        receipt.detector_outcome = PatchDetectorReplayOutcome::Failed;
        return finish_with_receipt(request, state, detail, receipt.clone(), detector);
    }
    if let Some(path) = changed_touched_path(request.target, &request.record)? {
        state = PatchLifecycleState::ChangedSinceApply;
        detail = format!("{path} changed during detector replay");
    }
    record_state(
        request.store,
        &mut request.record,
        state,
        Some(detail.clone()),
    )?;
    Ok(failed_reverify_output(&request.record, &detail))
}

fn finish_empirical_detector(
    request: ReverifyRequest<'_>,
    detector: &str,
    outcome: PatchLifecycleState,
    mut receipt: PatchReverificationReceipt,
) -> Result<Value> {
    let detector_outcome = detector_replay_outcome(outcome);
    let state = empirical_detector_state(None, detector_outcome);
    receipt.detector_outcome = detector_outcome;
    finish_with_receipt(request, state, outcome_detail(state), receipt, detector)
}

fn detector_replay_outcome(outcome: PatchLifecycleState) -> PatchDetectorReplayOutcome {
    match outcome {
        PatchLifecycleState::StillVulnerable => PatchDetectorReplayOutcome::Rediscovered,
        PatchLifecycleState::NotRediscovered => PatchDetectorReplayOutcome::NotRediscovered,
        _ => PatchDetectorReplayOutcome::Failed,
    }
}

fn finish_detector_without_receipt(
    mut request: ReverifyRequest<'_>,
    detector: &str,
    outcome: PatchLifecycleState,
) -> Result<Value> {
    if let Some(path) = changed_touched_path(request.target, &request.record)? {
        let detail = format!("{path} changed during detector replay");
        record_state(
            request.store,
            &mut request.record,
            PatchLifecycleState::ChangedSinceApply,
            Some(detail.clone()),
        )?;
        return Ok(failed_reverify_output(&request.record, &detail));
    }
    record_state(
        request.store,
        &mut request.record,
        outcome,
        Some(outcome_detail(outcome)),
    )?;
    Ok(completed_reverify_output(&request.record, detector))
}

pub(crate) fn finish_with_receipt(
    mut request: ReverifyRequest<'_>,
    mut state: PatchLifecycleState,
    mut detail: String,
    mut receipt: PatchReverificationReceipt,
    detector: &str,
) -> Result<Value> {
    bind_receipt_end(&request, &mut state, &mut detail, &mut receipt)?;
    let evidence = persist_receipt(request.target, &receipt)?;
    let evidence = confirm_receipt_end(&request, &mut state, &mut detail, &mut receipt, evidence)?;
    validate_verified_boundary(&request, state, &receipt)?;
    request.record.reverify_evidence = Some(evidence);
    record_state(
        request.store,
        &mut request.record,
        state,
        Some(detail.clone()),
    )?;
    Ok(reverify_output(&request, state, &detail, detector))
}

fn bind_receipt_end(
    request: &ReverifyRequest<'_>,
    state: &mut PatchLifecycleState,
    detail: &mut String,
    receipt: &mut PatchReverificationReceipt,
) -> Result<()> {
    let end = active_touched_hashes(request.target, &request.record)?;
    if end != receipt.start_touched_files {
        *state = PatchLifecycleState::ChangedSinceApply;
        *detail = "active patch files changed during empirical reverification".to_string();
    }
    receipt.end_touched_files = end;
    Ok(())
}

fn confirm_receipt_end(
    request: &ReverifyRequest<'_>,
    state: &mut PatchLifecycleState,
    detail: &mut String,
    receipt: &mut PatchReverificationReceipt,
    evidence: ObjectRef,
) -> Result<ObjectRef> {
    let confirmed = active_touched_hashes(request.target, &request.record)?;
    if confirmed == receipt.end_touched_files {
        return Ok(evidence);
    }
    *state = PatchLifecycleState::ChangedSinceApply;
    *detail = "active patch files changed before reverification persistence".to_string();
    receipt.end_touched_files = confirmed;
    persist_receipt(request.target, receipt)
}

fn validate_verified_boundary(
    request: &ReverifyRequest<'_>,
    state: PatchLifecycleState,
    receipt: &PatchReverificationReceipt,
) -> Result<()> {
    if state != PatchLifecycleState::Verified {
        return Ok(());
    }
    receipt.validate_for_verified()?;
    anyhow::ensure!(
        active_touched_hashes(request.target, &request.record)? == receipt.end_touched_files,
        "active patch files changed at the verified persistence boundary"
    );
    Ok(())
}

fn reverify_output(
    request: &ReverifyRequest<'_>,
    state: PatchLifecycleState,
    detail: &str,
    detector: &str,
) -> Value {
    match state {
        PatchLifecycleState::Failed | PatchLifecycleState::ChangedSinceApply => {
            failed_reverify_output(&request.record, detail)
        }
        _ => completed_reverify_output(&request.record, detector),
    }
}

pub(crate) fn empirical_outcome_detail(state: PatchLifecycleState) -> String {
    match state {
        PatchLifecycleState::StillVulnerable => {
            "an empirical attack survived on the patched source".to_string()
        }
        PatchLifecycleState::Failed => "the benign control regressed on patched source".to_string(),
        PatchLifecycleState::Inconclusive => {
            "the empirical attack ladder was inconclusive".to_string()
        }
        _ => outcome_detail(state),
    }
}
