//! Fixed finding review using the existing campaign dispatcher and allowance.
use super::{batch::equivalence::digest_serializable, *};
use crate::{
    allowance::{ApprovedWorkItem, ApprovedWorkPlanV1},
    modules::{ModuleRegistry, ToolExecutionContext},
    Finding,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

mod approval;
mod observation_sources;
pub(super) use approval::approve_review_work;
pub use observation_sources::ReviewObservationSource;

pub const REVIEW_STUDY_KIND: &str = "review-study";
const TOOL: &str = "triage:run";
const JOB: &str = "review-001";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewStudyReceipt {
    pub schema_version: u32,
    pub campaign_id: String,
    pub investigation_id: String,
    pub plan_sha256: String,
    pub source_identity: String,
    pub config_sha256: String,
    pub model: String,
    pub input: Value,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_sources: Vec<ReviewObservationSource>,
}

pub fn execute_review_study(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = ctx
        .workspace
        .context("review study requires a workspace")?
        .root();
    let (review, findings) = prepare_review(&input["reviewInput"], ctx)?;
    let id = string_input(input, &["campaignId"])
        .unwrap_or_else(|| crate::new_run_id(REVIEW_STUDY_KIND));
    validate_scan_batch_id(&id)?;
    let investigation = required_text(input, "investigationId")?;
    let document = plan_document(&id, &investigation, review, findings, ctx)?;
    let receipt = receipt_from_plan(&id, &document)?;
    std::fs::create_dir_all(campaigns_dir(root))?;
    std::fs::create_dir(campaign_dir(root, &id))
        .context("review study already exists; prepare a new draft")?;
    write_json_atomic(&campaign_plan_path(root, &id), &document)?;
    let summary = format!("Review draft: {id} · {} exact observations · one job · one worker\nModel: {} · strategy: {}\nSource: {}\nReview the exact work and shared allowance before execution. Internal turns and retries consume Review calls. Dollar consumption is uncertain. No jobs started.", receipt.findings.len(), receipt.model, receipt.input["strategy"].as_str().unwrap_or("unknown"), receipt.source_identity);
    Ok(crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        serde_json::to_value(receipt)?,
    ))
}

fn prepare_review(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<(Value, Vec<Finding>)> {
    let mut draft = input.clone();
    let object = draft
        .as_object_mut()
        .context("reviewInput must be an object")?;
    anyhow::ensure!(
        !object.contains_key("allowanceRef"),
        "approve the review plan separately from its input"
    );
    object.entry("concurrency").or_insert(json!(1));
    bind_review_context(&mut draft, ctx)?;
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry.prepare_dispatch_input(TOOL, draft, ctx, None)?;
    let mut frozen = prepared.value().clone();
    anyhow::ensure!(
        frozen["concurrency"] == 1,
        "review study uses one worker; separate work requires another plan"
    );
    let model = crate::tool_execution_model(TOOL, &frozen, ctx.config)
        .context("Select a model before planning review")?;
    frozen["model"] = json!(model);
    crate::modules::freeze_triage_review_input(&frozen, ctx)
}

fn plan_document(
    id: &str,
    investigation: &str,
    input: Value,
    findings: Vec<Finding>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = ctx
        .workspace
        .context("review study requires a workspace")?
        .root();
    Ok(
        json!({"schemaVersion":1,"kind":REVIEW_STUDY_KIND,"campaignId":id,
        "investigationId":investigation,"requiresWorkApproval":true,"tool":TOOL,
        "workers":1,"requestedWorkers":1,"effectiveWorkers":1,
        "sourceIdentity":crate::incremental_index::current_workspace_resume_identity(root)?,
        "configSha256":crate::config_hash(ctx.config)?,"model":input["model"],
        "observationSources":observation_sources::capture(root, &findings),
        "findings":findings,"jobs":[{"jobId":JOB,"tool":TOOL,"input":input}]}),
    )
}

fn bind_review_context(input: &mut Value, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    use crate::capabilities::threat_model::ThreatModelSelection;
    if ThreatModelSelection::from_input(input)?.is_bound() {
        return Ok(());
    }
    let root = ctx
        .workspace
        .context("review context requires a workspace")?
        .root();
    input["threatModelRef"]=match crate::workflow_attempts::accepted_map_context_selection(root)? {
        ThreatModelSelection::Revision(reference)=>serde_json::to_value(reference)?,
        ThreatModelSelection::None=>Value::Null,
        ThreatModelSelection::Active=>anyhow::bail!("No accepted Map context is bound. Select an exact context revision or explicitly omit it before preparing review"),
    };
    Ok(())
}

pub fn load_review_study(root: &Path, id: &str) -> Result<ReviewStudyReceipt> {
    receipt_from_plan(id, &super::approved_work::read_bounded_plan(root, id)?)
}

pub fn load_review_study_allowance(
    root: &Path,
    receipt: &ReviewStudyReceipt,
) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
    super::study_receipt::load_investigation_allowance(root, &receipt.investigation_id)
}

fn receipt_from_plan(id: &str, plan: &Value) -> Result<ReviewStudyReceipt> {
    validate_plan_shape(id, plan)?;
    let findings: Vec<Finding> = serde_json::from_value(plan["findings"].clone())?;
    let input = plan["jobs"][0]["input"].clone();
    validate_frozen_selection(plan, &findings, &input)?;
    let observation_sources = observation_sources::from_plan(plan, &findings)?;
    Ok(ReviewStudyReceipt {
        schema_version: 1,
        campaign_id: id.into(),
        investigation_id: required_text(plan, "investigationId")?,
        plan_sha256: digest_serializable(plan)?,
        source_identity: required_text(plan, "sourceIdentity")?,
        config_sha256: required_text(plan, "configSha256")?,
        model: required_text(plan, "model")?,
        input,
        findings,
        observation_sources,
    })
}

fn validate_frozen_selection(plan: &Value, findings: &[Finding], input: &Value) -> Result<()> {
    let references = findings
        .iter()
        .map(|finding| finding.id.map(|id| format!("generation:{id}")))
        .collect::<Option<Vec<_>>>()
        .context("review observations need exact generation ids")?;
    anyhow::ensure!(
        (1..=100).contains(&findings.len()) && input["fingerprints"] == json!(references),
        "review findings differ from the fixed selection"
    );
    anyhow::ensure!(
        input["model"] == plan["model"]
            && input["concurrency"] == 1
            && input.get("allowanceRef").is_none(),
        "review model, worker or allowance binding changed"
    );
    Ok(())
}

fn validate_plan_shape(id: &str, plan: &Value) -> Result<()> {
    anyhow::ensure!(
        plan["kind"] == REVIEW_STUDY_KIND && plan["schemaVersion"] == 1,
        "not a supported review study"
    );
    anyhow::ensure!(
        plan["campaignId"] == id && plan["requiresWorkApproval"] == true,
        "review identity or approval requirement changed"
    );
    anyhow::ensure!(
        plan["workers"] == 1
            && plan["requestedWorkers"] == 1
            && plan["effectiveWorkers"] == 1
            && plan["tool"] == TOOL,
        "review worker or tool changed"
    );
    anyhow::ensure!(
        plan["jobs"].as_array().is_some_and(|jobs| jobs.len() == 1)
            && plan["jobs"][0]["jobId"] == JOB
            && plan["jobs"][0]["tool"] == TOOL,
        "review permits one fixed triage job"
    );
    Ok(())
}

fn required_text(input: &Value, field: &str) -> Result<String> {
    input[field]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .with_context(|| format!("review study requires {field}"))
}

impl ReviewStudyReceipt {
    pub fn bound_input(&self, allowance: &crate::allowance::AllowanceSnapshot) -> Result<Value> {
        let plan = allowance
            .work_plan
            .as_ref()
            .context("review study is not approved")?;
        anyhow::ensure!(
            allowance.investigation_id == self.investigation_id
                && plan.campaign_id == self.campaign_id
                && plan.plan_sha256 == self.plan_sha256,
            "this review study is not the approved work"
        );
        let mut input = self.input.clone();
        input["allowanceRef"] = json!({"schemaVersion":1,"investigationId":self.investigation_id,"revision":allowance.revision,"workId":format!("{}:{JOB}",self.campaign_id)});
        Ok(input)
    }
}

#[cfg(test)]
mod tests;
