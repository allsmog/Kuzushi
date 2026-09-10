use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use serde_json::json;

/// Compile the existing scan-batch format without dispatching any children.
pub fn execute_study_plan(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = ctx
        .workspace
        .context("study planning requires an active workspace")?
        .root();
    let registry = ModuleRegistry::with_v2_builtins();
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
    let handle = batch::compile_study_plan(ScanBatchPlanSpec {
        root,
        batch_id: string_input(input, &["campaignId"]),
        trials: usize_input(input, &["trials"], 3),
        requested_workers: usize_input(input, &["workers"], 1),
        gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: prepared.value().clone(),
        config: ctx.config,
        registry: &registry,
    })?;
    let digest = campaign_plan_digest(root, &handle.campaign_id)?;
    let output = format!("Study draft: {} · {} discovery jobs · {} worker(s)\nPlan digest: {}\nSource identity: {}\nReview {} and approve this exact plan with an investigation allowance before execution. No jobs started.",
        handle.campaign_id, handle.trials_planned, handle.effective_workers, digest,
        handle.equivalence_key.components.workspace_identity, handle.plan_path.display());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "campaignId":handle.campaign_id, "planPath":handle.plan_path, "planSha256":digest,
            "jobCount":handle.trials_planned, "workers":handle.effective_workers,
            "equivalence":handle.equivalence_key, "approvalRequired":true,
        }),
    ))
}
