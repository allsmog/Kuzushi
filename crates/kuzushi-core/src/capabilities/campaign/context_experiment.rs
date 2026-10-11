//! A candidate study changes context only; its historical baseline is explicit.
use super::*;
use serde::{Deserialize, Serialize};

mod conditions;
#[cfg(test)]
mod tests;

pub(super) fn require_context_case_controls(
    baseline: &BatchEquivalenceKey,
    candidate: &BatchEquivalenceKey,
    baseline_input: &Value,
    candidate_input: &Value,
) -> Result<()> {
    conditions::require_unchanged_conditions(baseline, candidate)?;
    anyhow::ensure!(
        conditions::controlled_input_digest(baseline_input)?
            == conditions::controlled_input_digest(candidate_input)?,
        "Context cases change scanner options"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextExperimentReceipt {
    pub schema_version: u32,
    pub baseline_run_id: String,
    pub investigation_id: String,
    pub baseline: BatchEquivalenceKey,
    pub candidate: BatchEquivalenceKey,
    pub controlled_input_sha256: String,
}

pub(super) fn bind_context_experiment(
    root: &Path,
    run: &str,
    input: &Value,
    candidate: &BatchEquivalenceKey,
) -> Result<ContextExperimentReceipt> {
    let evidence = load_named_scan_usage(root, run)?;
    anyhow::ensure!(
        evidence.calibration_limitation.is_none(),
        "Context baseline is incomplete: {}",
        evidence
            .calibration_limitation
            .as_deref()
            .unwrap_or_default()
    );
    let baseline = evidence
        .equivalence
        .context("Context baseline has no authenticated condition receipt")?;
    let baseline_input = read_baseline_input(root, run, &baseline)?;
    let investigation_id = evidence.provider_usage.context("Context baseline has no durable investigation accounting; inspect historical results without starting a new experiment")?.investigation_id;
    let receipt = ContextExperimentReceipt {
        schema_version: 1,
        baseline_run_id: run.into(),
        investigation_id,
        baseline,
        candidate: candidate.clone(),
        controlled_input_sha256: conditions::controlled_input_digest(&baseline_input)?,
    };
    conditions::validate(&receipt, input, candidate)?;
    Ok(receipt)
}

fn read_baseline_input(root: &Path, run: &str, baseline: &BatchEquivalenceKey) -> Result<Value> {
    let (_, body) = crate::run_artifacts::read_run_artifact_text(root, run, "scan-input.json")
        .require("Context baseline scan input")?;
    let input: Value =
        serde_json::from_str(&body).context("Context baseline scan input is malformed")?;
    let input = conditions::bound_base_input(input);
    anyhow::ensure!(
        batch::equivalence::digest_serializable(&input)?
            == baseline.components.prepared_input_sha256,
        "Context baseline input disagrees with its condition receipt"
    );
    conditions::validate_context_binding(&input, baseline)?;
    Ok(input)
}

pub fn load_study_context_experiment(
    root: &Path,
    receipt: &StudyPlanReceipt,
) -> Result<Option<ContextExperimentReceipt>> {
    let plan = approved_work::read_bounded_plan(root, &receipt.campaign_id)?;
    anyhow::ensure!(
        batch::equivalence::digest_serializable(&plan)? == receipt.plan_sha256,
        "Context experiment belongs to a different plan revision"
    );
    load_frozen_experiment(&plan, &receipt.scan_input, &receipt.equivalence)
}

pub(super) fn load_frozen_experiment(
    plan: &Value,
    input: &Value,
    candidate: &BatchEquivalenceKey,
) -> Result<Option<ContextExperimentReceipt>> {
    let Some(value) = plan.get("contextExperiment") else {
        return Ok(None);
    };
    let receipt: ContextExperimentReceipt =
        serde_json::from_value(value.clone()).context("Context experiment receipt is malformed")?;
    conditions::validate(&receipt, input, candidate)?;
    anyhow::ensure!(
        plan["investigationId"].as_str() == Some(receipt.investigation_id.as_str()),
        "Context experiment must retain its baseline investigation accounting"
    );
    Ok(Some(receipt))
}

pub(super) fn bind_investigation(
    plan: &mut Value,
    receipt: &ContextExperimentReceipt,
) -> Result<()> {
    if let Some(id) = plan.get("investigationId") {
        anyhow::ensure!(id.as_str() == Some(receipt.investigation_id.as_str()), "Context experiment belongs to the baseline investigation; preserve its existing spending");
    }
    plan["investigationId"] = Value::String(receipt.investigation_id.clone());
    Ok(())
}

pub(super) fn verify_baseline_for_approval(
    root: &Path,
    plan: &Value,
    input: &Value,
    candidate: &BatchEquivalenceKey,
) -> Result<()> {
    let Some(frozen) = load_frozen_experiment(plan, input, candidate)? else {
        return Ok(());
    };
    let current = bind_context_experiment(root, &frozen.baseline_run_id, input, candidate)?;
    anyhow::ensure!(
        current == frozen,
        "Context baseline changed after planning; inspect it before preparing another draft"
    );
    Ok(())
}
