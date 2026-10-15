use super::*;
use crate::capabilities::threat_model::ThreatModelSelection;
use batch::equivalence::{digest_serializable, scan_batch_base_input};

pub(super) fn bound_base_input(input: Value) -> Value {
    let reference = input.get("threatModelRef").cloned();
    let mut base = scan_batch_base_input(input);
    if let Some(reference) = reference {
        base["threatModelRef"] = reference;
    }
    base
}

pub(super) fn controlled_input_digest(input: &Value) -> Result<String> {
    let mut input = bound_base_input(input.clone());
    let object = input
        .as_object_mut()
        .context("Context experiment input must be an object")?;
    object.remove("threatModelRef");
    object.remove("threatModelDigestRef");
    digest_serializable(&input)
}

pub(super) fn validate_context_binding(input: &Value, key: &BatchEquivalenceKey) -> Result<()> {
    let selected = ThreatModelSelection::from_input(input)?;
    anyhow::ensure!(selected.is_bound(), "Context experiments need exact revisions or explicit omission; active context is not a baseline");
    let expected = key
        .components
        .threat_model
        .as_ref()
        .unwrap_or(&Value::Null)
        .clone();
    anyhow::ensure!(
        input["threatModelRef"] == expected,
        "Context input disagrees with its consumed condition receipt"
    );
    Ok(())
}

pub(super) fn validate(
    receipt: &ContextExperimentReceipt,
    input: &Value,
    candidate: &BatchEquivalenceKey,
) -> Result<()> {
    anyhow::ensure!(
        receipt.schema_version == 1,
        "Unsupported context experiment schema"
    );
    validate_scan_batch_id(&receipt.baseline_run_id)?;
    validate_scan_batch_id(&receipt.investigation_id)?;
    authenticate_key(&receipt.baseline)?;
    authenticate_key(&receipt.candidate)?;
    anyhow::ensure!(
        &receipt.candidate == candidate,
        "Context experiment candidate differs from the frozen study"
    );
    validate_context_binding(input, candidate)?;
    anyhow::ensure!(
        controlled_input_digest(input)? == receipt.controlled_input_sha256,
        "Context experiment changes scan options; keep them fixed or plan a different experiment"
    );
    require_only_context_changes(&receipt.baseline, candidate)
}

fn authenticate_key(key: &BatchEquivalenceKey) -> Result<()> {
    anyhow::ensure!(
        digest_serializable(&key.components)? == key.sha256,
        "Context experiment condition receipt is not authenticated"
    );
    Ok(())
}

fn require_only_context_changes(
    baseline: &BatchEquivalenceKey,
    candidate: &BatchEquivalenceKey,
) -> Result<()> {
    anyhow::ensure!(baseline.components.threat_model != candidate.components.threat_model, "Context is unchanged. Use identical-condition repetitions or choose a different accepted context");
    require_unchanged_conditions(baseline, candidate)
}

pub(super) fn require_unchanged_conditions(
    baseline: &BatchEquivalenceKey,
    candidate: &BatchEquivalenceKey,
) -> Result<()> {
    let mut before = baseline.components.clone();
    let mut after = candidate.components.clone();
    for key in [&mut before, &mut after] {
        key.prepared_input_sha256.clear();
        key.threat_model = None;
    }
    anyhow::ensure!(before == after, "Context experiment changes source, scope, model, runtime, prompts, engine or tool configuration. Keep these conditions fixed");
    Ok(())
}
