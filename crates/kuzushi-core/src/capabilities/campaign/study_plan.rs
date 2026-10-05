use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};

/// Compile the existing scan-batch format without dispatching any children.
pub fn execute_study_plan(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = ctx
        .workspace
        .context("study planning requires an active workspace")?
        .root();
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared_input = prepare_study_scan_input(input, ctx, &registry)?;
    let investigation = string_input(input, &["investigationId"]);
    let handle = batch::compile_study_plan(
        ScanBatchPlanSpec {
            root,
            batch_id: string_input(input, &["campaignId"]),
            trials: usize_input(input, &["trials"], 3),
            requested_workers: usize_input(input, &["workers"], 1),
            gate_policy: ScanBatchGatePolicy::default(),
            prepared_input,
            config: ctx.config,
            registry: &registry,
        },
        investigation.as_deref(),
    )?;
    let receipt = load_study_plan_receipt(root, &handle.campaign_id)?;
    let output = format!("Study draft: {} · {} discovery jobs · {} worker(s)\nPlan digest: {}\nSource identity: {}\nReview {} and approve this exact plan with an investigation allowance before execution. No jobs started.",
        handle.campaign_id, handle.trials_planned, handle.effective_workers, receipt.plan_sha256,
        handle.equivalence_key.components.workspace_identity, handle.plan_path.display());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        serde_json::to_value(receipt)?,
    ))
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
    anyhow::ensure!(
        scan_input.get("allowanceRef").is_none(),
        "approve the resulting study plan before attaching its allowance"
    );
    let prepared = registry.prepare_dispatch_input("sast:scan", scan_input, ctx, None)?;
    crate::modules::validate_study_scan_selection(prepared.value())?;
    Ok(prepared.value().clone())
}
