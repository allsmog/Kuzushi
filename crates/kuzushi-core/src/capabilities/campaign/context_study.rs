//! One context draft in the existing campaign and investigation ledger.
use super::{approved_work::read_bounded_plan, batch::equivalence::digest_serializable, *};
use crate::{
    allowance::{ApprovedWorkItem, ApprovedWorkPlanV1},
    modules::{ModuleRegistry, ToolExecutionContext},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

mod input;
mod preparation;
mod recovery;
pub use preparation::ContextPreparationJob;

const TOOL: &str = "threat-model:build";
const JOB: &str = "context-001";
const KIND: &str = "context-study";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextStudyReceipt {
    pub campaign_id: String,
    pub investigation_id: String,
    pub plan_sha256: String,
    pub source_identity: String,
    pub config_sha256: String,
    pub model: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preparation_jobs: Vec<ContextPreparationJob>,
}

pub fn execute_context_study(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = ctx
        .workspace
        .context("context study requires a workspace")?
        .root();
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = input::prepare(
        input
            .get("contextInput")
            .context("contextInput is required")?,
        ctx,
        &registry,
    )?;
    let preparation = preparation::prepare_jobs(input.get("preparationJobs"), ctx, &registry)?;
    let id =
        string_input(input, &["campaignId"]).unwrap_or_else(|| crate::new_run_id("context-study"));
    validate_scan_batch_id(&id)?;
    let investigation = input["investigationId"]
        .as_str()
        .context("investigationId is required")?;
    let document = plan_document(&id, investigation, prepared, &preparation, ctx)?;
    let receipt = receipt_from_plan(&id, &document)?;
    let directory = campaign_dir(root, &id);
    std::fs::create_dir_all(campaigns_dir(root))?;
    std::fs::create_dir(&directory).context("context study already exists; create a new draft")?;
    write_json_atomic(&campaign_plan_path(root, &id), &document)?;
    let summary = format!("Context study draft: {id} · {} jobs · one worker\nModel: {}\nSource: {}\nApprove its exact plan and allowance before generation. No jobs started.", receipt.job_count(), receipt.model, receipt.source_identity);
    Ok(crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        serde_json::to_value(receipt)?,
    ))
}

fn plan_document(
    id: &str,
    investigation: &str,
    input: Value,
    preparation: &[ContextPreparationJob],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = ctx
        .workspace
        .context("context study requires a workspace")?
        .root();
    let model = input["model"]
        .as_str()
        .context("context study needs an explicit selected model")?;
    Ok(json!({
        "schemaVersion":1, "kind":KIND, "campaignId":id, "investigationId":investigation,
        "requiresWorkApproval":true, "tool":TOOL, "workers":1,
        "requestedWorkers":1, "effectiveWorkers":1,
        "sourceIdentity":crate::incremental_index::current_workspace_resume_identity(root)?,
        "configSha256":crate::config_hash(ctx.config)?, "model":model,
        "jobs":preparation::plan_jobs(input.clone(), preparation),
    }))
}

pub fn load_context_study(root: &Path, id: &str) -> Result<ContextStudyReceipt> {
    receipt_from_plan(id, &read_bounded_plan(root, id)?)
}

fn receipt_from_plan(id: &str, plan: &Value) -> Result<ContextStudyReceipt> {
    validate_context_identity(id, plan)?;
    let jobs = plan["jobs"]
        .as_array()
        .context("context study has no jobs")?;
    anyhow::ensure!(
        (1..=3).contains(&jobs.len()),
        "context study must contain one generation job and at most two preparation jobs"
    );
    anyhow::ensure!(
        plan["workers"] == 1
            && plan["effectiveWorkers"] == 1
            && plan["requestedWorkers"] == 1
            && plan["tool"] == TOOL,
        "context study worker or tool declaration changed"
    );
    let context_job = jobs.last().unwrap();
    let preparation_jobs = preparation::read_jobs(&jobs[..jobs.len() - 1])?;
    anyhow::ensure!(
        context_job["jobId"] == JOB && context_job["tool"] == TOOL,
        "context study job changed"
    );
    input::validate(&context_job["input"])?;
    anyhow::ensure!(
        plan["model"] == context_job["input"]["model"],
        "context study model differs from its job"
    );
    Ok(ContextStudyReceipt {
        campaign_id: id.into(),
        investigation_id: required_text(plan, "investigationId")?,
        plan_sha256: digest_serializable(plan)?,
        source_identity: required_text(plan, "sourceIdentity")?,
        config_sha256: required_text(plan, "configSha256")?,
        model: required_text(plan, "model")?,
        input: context_job["input"].clone(),
        preparation_jobs,
    })
}

fn validate_context_identity(id: &str, plan: &Value) -> Result<()> {
    anyhow::ensure!(
        plan["kind"] == KIND && plan["schemaVersion"] == 1,
        "not a supported context study"
    );
    anyhow::ensure!(
        plan["campaignId"] == id && plan["requiresWorkApproval"] == true,
        "context study identity or approval requirement changed"
    );
    Ok(())
}

fn required_text(value: &Value, key: &str) -> Result<String> {
    value[key]
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned)
        .with_context(|| format!("context study needs {key}"))
}

pub(super) fn approve_context_work(
    id: &str,
    approval: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<ApprovedWorkPlanV1>> {
    let root = ctx
        .workspace
        .context("context study requires a workspace")?
        .root();
    let plan = read_bounded_plan(root, id)?;
    if plan["kind"] != KIND {
        return Ok(None);
    }
    let receipt = receipt_from_plan(id, &plan)?;
    validate_approval(&receipt, approval, ctx)?;
    let attempts = approval["maxJobAttempts"]
        .as_u64()
        .context("maxJobAttempts is required")?;
    anyhow::ensure!(
        attempts == 1,
        "context study permits one attempt; prepare and approve another draft for regeneration"
    );
    Ok(Some(ApprovedWorkPlanV1 {
        schema_version: 1,
        campaign_id: id.into(),
        plan_sha256: receipt.plan_sha256.clone(),
        source_identity: receipt.source_identity.clone(),
        config_sha256: receipt.config_sha256.clone(),
        jobs: preparation::approved_jobs(&receipt)?,
    }))
}

fn validate_approval(
    receipt: &ContextStudyReceipt,
    approval: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    anyhow::ensure!(
        approval["investigationId"] == receipt.investigation_id,
        "context study belongs to a different investigation; preserve existing accounting"
    );
    anyhow::ensure!(
        approval["campaignPlanSha256"] == receipt.plan_sha256
            && approval["campaignJobs"] == receipt.job_count(),
        "context study digest or job count changed; review the current plan"
    );
    anyhow::ensure!(
        approval["model"] == receipt.model,
        "allowance model differs from context study"
    );
    validate_current_inputs(receipt, ctx)
}

fn validate_current_inputs(
    receipt: &ContextStudyReceipt,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = input::prepare(&receipt.input, ctx, &registry)?;
    anyhow::ensure!(
        prepared == receipt.input,
        "context options changed; prepare a new draft"
    );
    let preparation = preparation::prepare_jobs(
        Some(&serde_json::to_value(&receipt.preparation_jobs)?),
        ctx,
        &registry,
    )?;
    anyhow::ensure!(
        preparation == receipt.preparation_jobs,
        "context preparation changed; prepare a new draft"
    );
    let current = plan_document(
        &receipt.campaign_id,
        &receipt.investigation_id,
        prepared,
        &preparation,
        ctx,
    )?;
    anyhow::ensure!(
        current["sourceIdentity"] == receipt.source_identity
            && current["configSha256"] == receipt.config_sha256,
        "context study source or configuration changed; prepare a new draft"
    );
    Ok(())
}

impl ContextStudyReceipt {
    pub fn job_count(&self) -> usize {
        self.preparation_jobs.len() + 1
    }

    pub fn bound_input(&self, allowance: &crate::allowance::AllowanceSnapshot) -> Result<Value> {
        let plan = allowance
            .work_plan
            .as_ref()
            .context("context study is not approved")?;
        anyhow::ensure!(
            allowance.investigation_id == self.investigation_id
                && plan.campaign_id == self.campaign_id
                && plan.plan_sha256 == self.plan_sha256,
            "this context study is not the approved work"
        );
        let mut input = self.input.clone();
        input["allowanceRef"] = json!({"schemaVersion":1,"investigationId":self.investigation_id,"revision":allowance.revision,"workId":format!("{}:{JOB}",self.campaign_id)});
        Ok(input)
    }
}

#[cfg(test)]
mod tests;
