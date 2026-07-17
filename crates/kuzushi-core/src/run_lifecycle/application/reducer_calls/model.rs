use super::super::super::super::{CallKind, CallProjection, RunProjection};
use super::super::ensure_legacy;
use super::{ensure_call_identity, new_call, required_call_id};
use crate::run_lifecycle::{ModelUsage, RunCallId, RunItemEnvelopeV1, RunItemStatus, SafeText};
use crate::runtime::RuntimeCostReport;
use anyhow::Result;

pub(in crate::run_lifecycle::application) fn start_model_call(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    provider: &SafeText,
    model: &SafeText,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    anyhow::ensure!(
        !projection.calls.contains_key(&call_id),
        "model call started twice"
    );
    let mut call = new_call(envelope, CallKind::Model, model, RunItemStatus::Running);
    call.provider = Some(provider.clone());
    call.model = Some(model.clone());
    call.started_at_ms = Some(envelope.occurred_at_ms);
    projection.calls.insert(call_id, call);
    projection.call_order.push(call_id);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::run_lifecycle::application) fn apply_model_finished(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    provider: &SafeText,
    model: &SafeText,
    status: RunItemStatus,
    latency_ms: u64,
    usage: &ModelUsage,
    cost: RuntimeCostReport,
    error_class: &Option<SafeText>,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    ensure_model_call_exists(projection, envelope, call_id, model)?;
    let call = projection
        .calls
        .get_mut(&call_id)
        .expect("model call was inserted above");
    validate_model_finish(call, envelope, provider, model, status)?;
    apply_model_finish(
        call,
        envelope,
        provider,
        model,
        status,
        latency_ms,
        usage,
        cost,
        error_class,
    );
    projection.observed_model_cost = projection
        .observed_model_cost
        .checked_add(cost, "run lifecycle model cost")?;
    Ok(())
}

fn ensure_model_call_exists(
    projection: &mut RunProjection,
    envelope: &RunItemEnvelopeV1,
    call_id: RunCallId,
    model: &SafeText,
) -> Result<()> {
    if let std::collections::btree_map::Entry::Vacant(entry) = projection.calls.entry(call_id) {
        ensure_legacy(envelope, "model finish without start")?;
        entry.insert(new_call(
            envelope,
            CallKind::Model,
            model,
            RunItemStatus::Running,
        ));
        projection.call_order.push(call_id);
    }
    Ok(())
}

fn validate_model_finish(
    call: &CallProjection,
    envelope: &RunItemEnvelopeV1,
    provider: &SafeText,
    model: &SafeText,
    status: RunItemStatus,
) -> Result<()> {
    anyhow::ensure!(status.is_terminal(), "model call finish is not terminal");
    anyhow::ensure!(
        call.status == RunItemStatus::Running,
        "model call finished from invalid state"
    );
    ensure_call_identity(call, envelope)?;
    anyhow::ensure!(&call.label == model, "model changed during call");
    if let Some(start_provider) = call.provider.as_ref() {
        anyhow::ensure!(start_provider == provider, "provider changed during call");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_model_finish(
    call: &mut CallProjection,
    envelope: &RunItemEnvelopeV1,
    provider: &SafeText,
    model: &SafeText,
    status: RunItemStatus,
    latency_ms: u64,
    usage: &ModelUsage,
    cost: RuntimeCostReport,
    error_class: &Option<SafeText>,
) {
    call.provider = Some(provider.clone());
    call.model = Some(model.clone());
    call.status = status;
    call.completed_at_ms = Some(envelope.occurred_at_ms);
    call.latency_ms = Some(latency_ms);
    call.usage = usage.clone();
    call.cost = cost;
    call.error_class = error_class.clone();
}
