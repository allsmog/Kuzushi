//! Bind existing scan-batch jobs to an explicitly approved allowance.
use super::{batch::equivalence::digest_serializable, *};
use crate::{
    allowance::{ApprovedWorkItem, ApprovedWorkPlanV1},
    modules::{ModuleRegistry, ToolExecutionContext},
};
use std::io::Read;

pub fn campaign_plan_digest(root: &Path, id: &str) -> Result<String> {
    digest_serializable(&read_bounded_plan(root, id)?)
}

pub(super) fn approve_work(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<ApprovedWorkPlanV1>> {
    let Some(id) = input.get("campaignId").and_then(Value::as_str) else {
        anyhow::ensure!(
            !["campaignPlanSha256", "campaignJobs", "maxJobAttempts"]
                .iter()
                .any(|key| input.get(key).is_some()),
            "campaign work approval requires campaignId"
        );
        return Ok(None);
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let (plan, digest, current) = review_campaign(id, input, ctx, &registry)?;
    let attempts = input["maxJobAttempts"]
        .as_u64()
        .context("maxJobAttempts is required for campaign approval")?;
    let jobs = plan["jobs"]
        .as_array()
        .context("campaign has no jobs")?
        .iter()
        .map(|job| approved_job(id, job, attempts, &registry, ctx))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(ApprovedWorkPlanV1 {
        schema_version: 1,
        campaign_id: id.into(),
        plan_sha256: digest,
        source_identity: current.components.workspace_identity,
        config_sha256: current.components.config_sha256,
        jobs,
    }))
}

fn review_campaign(id: &str, input: &Value, ctx: &ToolExecutionContext<'_>, registry: &ModuleRegistry) -> Result<(Value, String, BatchEquivalenceKey)> {
    let root = ctx
        .workspace
        .context("campaign approval requires a workspace")?
        .root();
    let plan = read_bounded_plan(root, id)?;
    let digest = digest_serializable(&plan)?;
    anyhow::ensure!(
        input["campaignPlanSha256"].as_str() == Some(&digest),
        "campaign plan changed; review its current digest"
    );
    let checked = validate_scan_batch_execution_plan(id, &plan)?;
    validate_discovery_input(&checked.base_input)?;
    anyhow::ensure!(
        input["campaignJobs"].as_u64() == Some(checked.trials_planned as u64),
        "approved job count differs from the campaign"
    );
    let current = capture_batch_equivalence(root, &checked.base_input, ctx.config, registry)?;
    anyhow::ensure!(
        current.sha256 == checked.equivalence_key,
        "campaign source, context, model or configuration changed; compile a new plan"
    );
    if let Some(model) = &current.components.model {
        anyhow::ensure!(
            input["model"].as_str() == Some(model),
            "allowance model differs from the frozen campaign model"
        );
    }
    Ok((plan, digest, current))
}

fn validate_discovery_input(input: &Value) -> Result<()> {
    for key in ["triage", "verify", "autoPatch"] {
        anyhow::ensure!(
            input.get(key) == Some(&Value::Bool(false)),
            "approved batch must freeze {key}=false"
        );
    }
    Ok(())
}

fn approved_job(
    id: &str,
    job: &Value,
    attempts: u64,
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ApprovedWorkItem> {
    let job_id = job["jobId"].as_str().context("campaign job has no id")?;
    let prepared = registry.prepare_dispatch_input("sast:scan", job["input"].clone(), ctx, None)?;
    Ok(ApprovedWorkItem {
        work_id: format!("{id}:{job_id}"),
        tool: "sast:scan".into(),
        input_sha256: work_input_digest(prepared.value())?,
        max_attempts: u32::try_from(attempts).context("invalid attempt count")?,
    })
}

/// Run identity and allowance attribution are transport metadata. All scanner
/// options, including batch/trial identity and context references, stay bound.
pub fn work_input_digest(input: &Value) -> Result<String> {
    let mut input = input.clone();
    let object = input
        .as_object_mut()
        .context("work input must be an object")?;
    for key in ["allowanceRef", "runId", "run_id"] {
        object.remove(key);
    }
    digest_serializable(&input)
}

fn read_bounded_plan(root: &Path, id: &str) -> Result<Value> {
    validate_scan_batch_id(id)?;
    let path = campaign_plan_path(root, id);
    let mut bytes = Vec::new();
    std::fs::File::open(&path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "campaign plan exceeds the 4 MiB approval limit"
    );
    serde_json::from_slice(&bytes).context("campaign plan is malformed")
}

pub(crate) fn require_study_reference(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    let Some(batch) = input.get("batchId").and_then(Value::as_str) else {
        return Ok(());
    };
    let workspace = ctx
        .workspace
        .context("scan-batch work requires a workspace")?;
    let plan = read_bounded_plan(workspace.root(), batch)?;
    let bound = crate::SpendLimiter::read_campaign_allowance(&workspace.findings_db_path(), batch)?;
    let Some(bound) = bound else {
        anyhow::ensure!(
            plan.get("requiresWorkApproval") != Some(&Value::Bool(true)),
            "study requires approval of its exact jobs and allowance before execution"
        );
        return Ok(());
    };
    let approved = bound
        .work_plan
        .as_ref()
        .context("campaign has no approved work")?;
    anyhow::ensure!(
        digest_serializable(&plan)? == approved.plan_sha256,
        "campaign plan changed after approval"
    );
    let reference: crate::allowance::AllowanceReferenceV1 = serde_json::from_value(
        input
            .get("allowanceRef")
            .cloned()
            .context("study child requires its approved allowance reference")?,
    )?;
    reference.validate()?;
    anyhow::ensure!(
        reference.investigation_id == bound.investigation_id
            && reference.revision == bound.revision,
        "study child cannot substitute another allowance"
    );
    approved.job(&reference.work_id)?;
    Ok(())
}
