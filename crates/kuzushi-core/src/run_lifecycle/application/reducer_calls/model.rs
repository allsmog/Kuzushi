use super::super::super::super::{CallKind, CallProjection, RunProjection};
use super::{ensure_call_identity, new_call, required_call_id};
use crate::run_lifecycle::{ModelUsage, RunItemEnvelopeV1, RunItemStatus, SafeText};
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
    failure: &Option<crate::runtime::RuntimeFailureMetadata>,
) -> Result<()> {
    let call_id = required_call_id(envelope)?;
    let first_model_receipt = !projection
        .calls
        .values()
        .any(|call| call.kind == CallKind::Model && call.status.is_terminal());
    let call = projection
        .calls
        .get_mut(&call_id)
        .ok_or_else(|| anyhow::anyhow!("model finish without start"))?;
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
        failure,
    );
    record_model_cost(projection, first_model_receipt, cost)
}

fn record_model_cost(
    projection: &mut RunProjection,
    first_model_receipt: bool,
    cost: RuntimeCostReport,
) -> Result<()> {
    projection.observed_model_cost = if first_model_receipt {
        cost
    } else {
        projection
            .observed_model_cost
            .checked_add(cost, "run lifecycle model cost")?
    };
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
    failure: &Option<crate::runtime::RuntimeFailureMetadata>,
) {
    call.provider = Some(provider.clone());
    call.model = Some(model.clone());
    call.status = status;
    call.completed_at_ms = Some(envelope.occurred_at_ms);
    call.latency_ms = Some(latency_ms);
    call.usage = usage.clone();
    call.cost = cost;
    call.error_class = error_class.clone();
    call.failure = failure.clone();
}
