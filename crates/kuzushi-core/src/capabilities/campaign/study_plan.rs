use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};

/// Compile the existing scan-batch format without dispatching any children.
pub fn execute_study_plan(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    if let Some(scopes) = ScopeStudyDraft::from_input(input)? {
        return scope_study::compile_scope_study(input, scopes, ctx);
    }
    if let Some(matrix) = ContextMatrixDraft::from_input(input)? {
        return context_matrix::compile_context_matrix(input, matrix, ctx);
    }
    require_resource_case_selection(input)?;
    execute_scan_study(input, ctx)
}

fn require_resource_case_selection(input: &Value) -> Result<()> {
    anyhow::ensure!(
        input.get("resourceBaselineCampaignId").is_none(),
        "resourceBaselineCampaignId requires scopeCases or contextCases"
    );
    Ok(())
}

fn execute_scan_study(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = ctx
        .workspace
        .context("study planning requires an active workspace")?
        .root();
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared_input = prepare_study_scan_input(input, ctx, &registry)?;
    let investigation = super::map_allowance::study_investigation(input, root, &prepared_input)?;
    let baseline = input
        .get("baselineRunId")
        .map(|value| value.as_str().context("baselineRunId must be a string"))
        .transpose()?;
    let spec = ScanBatchPlanSpec {
        root,
        batch_id: string_input(input, &["campaignId"]),
        trials: usize_input(input, &["trials"], 3),
        requested_workers: usize_input(input, &["workers"], 1),
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input,
        config: ctx.config,
        registry: &registry,
    };
    let handle = compile_selected_study(spec, investigation.as_deref(), baseline, input)?;
    let receipt = load_study_plan_receipt(root, &handle.campaign_id)?;
    let output = format!("Study draft: {} · {} discovery jobs · {} worker(s)\nPlan digest: {}\nSource identity: {}\nReview {} and approve this exact plan with an investigation allowance before execution. No jobs started.",
        handle.campaign_id, handle.trials_planned, handle.effective_workers, receipt.plan_sha256,
        handle.equivalence_key.components.workspace_identity, handle.plan_path.display());
    let mut data = serde_json::to_value(&receipt)?;
    if let Some(experiment) = load_study_context_experiment(root, &receipt)? {
        data["contextExperiment"] = serde_json::to_value(experiment)?;
    }
    if let Some(run) = baseline {
        data["resourceBaselineRunId"] = Value::String(run.into());
    }
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        data,
    ))
}

fn compile_selected_study(
    spec: ScanBatchPlanSpec<'_>,
    investigation: Option<&str>,
    baseline: Option<&str>,
    input: &Value,
) -> Result<CampaignPlanHandle> {
    let brief = super::brief::from_input(spec.root, input)?;
    if let Some(value) = input.get("contextBaselineRunId") {
        let run = value
            .as_str()
            .context("contextBaselineRunId must be a string")?;
        return batch::compile_context_candidate_plan(
            spec,
            investigation,
            baseline,
            run,
            brief.as_ref(),
        );
    }
    batch::compile_study_plan_with_baseline(spec, investigation, baseline, brief.as_ref())
}

fn prepare_study_scan_input(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Value> {
    let mut scan_input = input
        .get("scanInput")
        .cloned()
        .context("scanInput is required")?;
    batch::equivalence::force_discovery_only(&mut scan_input)?;
    bind_accepted_map_context(&mut scan_input, ctx)?;
    anyhow::ensure!(
        scan_input.get("allowanceRef").is_none(),
        "approve the resulting study plan before attaching its allowance"
    );
    let prepared = registry.prepare_dispatch_input("sast:scan", scan_input, ctx, None)?;
    crate::modules::validate_study_scan_selection(prepared.value())?;
    Ok(prepared.value().clone())
}

pub(super) fn bind_accepted_map_context(
    input: &mut Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    use crate::capabilities::threat_model::ThreatModelSelection;
    if ThreatModelSelection::from_input(input)?.is_bound() {
        return Ok(());
    }
    let root = ctx
        .workspace
        .context("study planning requires a workspace")?
        .root();
    match crate::workflow_attempts::accepted_map_context_selection(root)? {
        ThreatModelSelection::Active => {}
        ThreatModelSelection::None => input["threatModelRef"] = Value::Null,
        ThreatModelSelection::Revision(reference) => {
            input["threatModelRef"] = serde_json::to_value(reference)?
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_context_omission_does_not_read_or_inherit_map_history() {
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        for key in ["threatModelRef", "threat_model_ref"] {
            let mut input = serde_json::json!({key: null});
            bind_accepted_map_context(&mut input, &ctx).unwrap();
            assert!(input[key].is_null());
        }
        assert!(bind_accepted_map_context(&mut serde_json::json!({}), &ctx).is_err());
    }
}
