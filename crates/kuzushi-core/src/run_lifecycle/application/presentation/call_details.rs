use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct CallDetails {
    pub runtime: Option<SafeText>,
    pub model: Option<SafeText>,
    pub provider: Option<SafeText>,
    pub safe_option_names: Vec<SafeText>,
    pub preview: Vec<SafeText>,
    pub warning_count: u64,
    pub error_count: u64,
    pub result_artifact: Option<ArtifactReference>,
    pub rejection: Option<CallRejectionPresentationV1>,
    pub latency_ms: Option<u64>,
    pub usage: Option<ModelUsage>,
    pub error_class: Option<SafeText>,
    pub failure: Option<crate::runtime::RuntimeFailureMetadata>,
    pub timing: CallTimingV1,
}

pub(super) fn call_details(projection: &RunProjection) -> BTreeMap<RunCallId, CallDetails> {
    let mut details = BTreeMap::new();
    for envelope in &projection.timeline {
        let Some(call_id) = envelope.call_id else {
            continue;
        };
        apply_call_item(details.entry(call_id).or_default(), envelope);
    }
    details
}

fn apply_call_item(details: &mut CallDetails, envelope: &RunItemEnvelopeV1) {
    if !apply_tool_call_item(details, envelope) {
        apply_model_call_item(details, envelope);
    }
}

fn apply_tool_call_item(details: &mut CallDetails, envelope: &RunItemEnvelopeV1) -> bool {
    match &envelope.item {
        RunItemV1::ToolCallRequested {
            safe_option_names, ..
        } => apply_request(details, safe_option_names, envelope.occurred_at_ms),
        RunItemV1::ToolCallStarted { runtime, model, .. } => {
            apply_start(details, runtime, model, envelope.occurred_at_ms)
        }
        RunItemV1::ToolCallRejected {
            reason_class,
            detail,
        } => apply_rejection(details, reason_class, detail, envelope.occurred_at_ms),
        RunItemV1::ToolCallFinished {
            result_artifact,
            preview,
            warning_count,
            error_count,
            ..
        } => apply_tool_finish(
            details,
            result_artifact,
            preview,
            (*warning_count, *error_count),
            envelope.occurred_at_ms,
        ),
        _ => return false,
    }
    true
}

fn apply_request(details: &mut CallDetails, options: &[SafeText], occurred_at_ms: u64) {
    details.safe_option_names = options.to_vec();
    details.timing.requested_at_ms = Some(occurred_at_ms);
}

fn apply_start(
    details: &mut CallDetails,
    runtime: &Option<SafeText>,
    model: &Option<SafeText>,
    occurred_at_ms: u64,
) {
    details.runtime = runtime.clone();
    details.model = model.clone();
    details.timing.started_at_ms = Some(occurred_at_ms);
}

fn apply_rejection(
    details: &mut CallDetails,
    reason_class: &SafeText,
    detail: &SafeText,
    occurred_at_ms: u64,
) {
    details.rejection = Some(CallRejectionPresentationV1 {
        reason_class: reason_class.clone(),
        detail: detail.clone(),
    });
    details.timing.finished_at_ms = Some(occurred_at_ms);
}

fn apply_tool_finish(
    details: &mut CallDetails,
    result_artifact: &Option<ArtifactReference>,
    preview: &[SafeText],
    counts: (u64, u64),
    occurred_at_ms: u64,
) {
    details.result_artifact = result_artifact.clone();
    details.preview = preview.to_vec();
    (details.warning_count, details.error_count) = counts;
    details.timing.finished_at_ms = Some(occurred_at_ms);
}

fn apply_model_call_item(details: &mut CallDetails, envelope: &RunItemEnvelopeV1) {
    match &envelope.item {
        RunItemV1::ModelCallStarted {
            provider, model, ..
        } => apply_model_start(details, provider, model, envelope.occurred_at_ms),
        RunItemV1::ModelCallFinished {
            provider,
            model,
            latency_ms,
            usage,
            error_class,
            failure,
            ..
        } => apply_model_finish(
            details,
            (provider, model),
            *latency_ms,
            usage,
            error_class,
            failure,
            envelope.occurred_at_ms,
        ),
        _ => {}
    }
}

fn apply_model_start(
    details: &mut CallDetails,
    provider: &SafeText,
    model: &SafeText,
    occurred_at_ms: u64,
) {
    details.provider = Some(provider.clone());
    details.model = Some(model.clone());
    details.timing.started_at_ms = Some(occurred_at_ms);
}

fn apply_model_finish(
    details: &mut CallDetails,
    identity: (&SafeText, &SafeText),
    latency_ms: u64,
    usage: &ModelUsage,
    error_class: &Option<SafeText>,
    failure: &Option<crate::runtime::RuntimeFailureMetadata>,
    occurred_at_ms: u64,
) {
    details.provider = Some(identity.0.clone());
    details.model = Some(identity.1.clone());
    details.latency_ms = Some(latency_ms);
    details.usage = Some(usage.clone());
    details.error_class = error_class.clone();
    details.failure = failure.clone();
    details.timing.finished_at_ms = Some(occurred_at_ms);
}
