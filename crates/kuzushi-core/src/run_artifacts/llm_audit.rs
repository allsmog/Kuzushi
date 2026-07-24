use super::RunLlmCallAudit;
use crate::run_lifecycle::{read_run_items, ProjectionHealth, RunCallId, RunItemV1};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) struct RunLifecycleAudit {
    pub(crate) llm_calls: Vec<RunLlmCallAudit>,
    pub(crate) malformed_lines: usize,
}

pub(crate) fn load_run_lifecycle_audit(target: &Path, run_id: &str) -> RunLifecycleAudit {
    let Ok(Some(read)) = read_run_items(target, run_id) else {
        return empty_audit();
    };
    let malformed_lines = usize::from(matches!(read.health, ProjectionHealth::Degraded { .. }));
    let fingerprints = model_fingerprints(&read.items);
    let llm_calls = read
        .items
        .into_iter()
        .filter_map(|envelope| audit_call(envelope, &fingerprints))
        .collect();
    RunLifecycleAudit { llm_calls, malformed_lines }
}

fn empty_audit() -> RunLifecycleAudit {
    RunLifecycleAudit { llm_calls: Vec::new(), malformed_lines: 0 }
}

fn model_fingerprints(
    items: &[crate::run_lifecycle::RunItemEnvelopeV1],
) -> BTreeMap<RunCallId, String> {
    items
        .iter()
        .filter_map(|envelope| match (&envelope.call_id, &envelope.item) {
            (Some(call_id), RunItemV1::ModelCallStarted { operation_fingerprint, .. }) => {
                Some((*call_id, operation_fingerprint.as_str().to_string()))
            }
            _ => None,
        })
        .collect()
}

fn audit_call(
    envelope: crate::run_lifecycle::RunItemEnvelopeV1,
    fingerprints: &BTreeMap<RunCallId, String>,
) -> Option<RunLlmCallAudit> {
    let RunItemV1::ModelCallFinished {
        provider,
        model,
        status,
        latency_ms,
        cost,
        ..
    } = envelope.item else {
        return None;
    };
    Some(RunLlmCallAudit {
        n: envelope.seq as usize,
        kind: status.label().to_string(),
        verb: None,
        model: model.to_string(),
        provider: provider.to_string(),
        prompt_hash: envelope
            .call_id
            .and_then(|call_id| fingerprints.get(&call_id).cloned())
            .unwrap_or_else(|| "unavailable".to_string()),
        latency_ms: Some(latency_ms),
        cost_usd: cost.exact_usd(),
        observed_cost_usd: (!cost.is_complete()).then(|| cost.observed_usd()),
        provider_spend_unresolved: !cost.is_complete(),
        call_attempted: Some(true),
    })
}
