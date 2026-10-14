//! Preserve legacy condition keys while making root-context omission comparable.
use super::*;
use crate::capabilities::threat_model::{
    current_scope_ref_for_path, load_threat_model_manifest, ThreatModelRef,
};

pub(super) fn capture_omission_scope(root: &Path, input: &Value) -> Result<Option<String>> {
    let Some(reference) = input.get("threatModelRef").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let reference: ThreatModelRef = serde_json::from_value(reference.clone())?;
    let manifest = load_threat_model_manifest(root)?.context("Bound context has no manifest")?;
    let scope = manifest
        .models
        .iter()
        .find(|model| model.model_id == reference.model_id)
        .context("Bound context lineage is absent")?;
    let current =
        current_scope_ref_for_path(root, ".")?.context("Root context scope is unavailable")?;
    if !scope.scope.same_lineage_category(&current) {
        return Ok(None);
    }
    let mut omitted = input.clone();
    omitted["threatModelRef"] = Value::Null;
    batch::equivalence::scope_sha256(root, &omitted).map(Some)
}

pub(super) fn require_case_conditions(
    baseline: &FrozenContextCase,
    candidate: &FrozenContextCase,
) -> Result<()> {
    validate_projection(baseline)?;
    validate_projection(candidate)?;
    let mut before = baseline.equivalence.clone();
    let mut after = candidate.equivalence.clone();
    project_against_omission(&mut after, candidate, &baseline.equivalence)?;
    project_against_omission(&mut before, baseline, &candidate.equivalence)?;
    super::super::context_experiment::require_context_case_controls(
        &before,
        &after,
        &baseline.base_input,
        &candidate.base_input,
    )
}

fn project_against_omission(
    key: &mut BatchEquivalenceKey,
    case: &FrozenContextCase,
    other: &BatchEquivalenceKey,
) -> Result<()> {
    if other.components.threat_model.is_some() || key.components.threat_model.is_none() {
        return Ok(());
    }
    apply_omission_projection(key, case)
}

pub(super) fn validate_current_projection(root: &Path, case: &FrozenContextCase) -> Result<()> {
    if case.omission_scope_sha256.is_none() {
        return Ok(());
    }
    anyhow::ensure!(capture_omission_scope(root, &case.base_input)? == case.omission_scope_sha256,
        "Root-scope comparison differs from the selected context or source. Prepare a new fixed matrix.");
    Ok(())
}

fn apply_omission_projection(
    key: &mut BatchEquivalenceKey,
    case: &FrozenContextCase,
) -> Result<()> {
    key.components.scope_sha256 = case.omission_scope_sha256.clone()
        .context("Context omission needs a new fixed matrix with an authenticated root-scope comparison. The existing plan is unchanged.")?;
    Ok(())
}

fn validate_projection(case: &FrozenContextCase) -> Result<()> {
    let Some(projection) = &case.omission_scope_sha256 else {
        return Ok(());
    };
    anyhow::ensure!(
        case.equivalence.components.threat_model.is_some(),
        "An omitted context cannot carry a root-scope comparison"
    );
    let digest = projection
        .strip_prefix("sha256:")
        .context("Root-scope comparison digest is malformed")?;
    anyhow::ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Root-scope comparison digest is malformed"
    );
    Ok(())
}
