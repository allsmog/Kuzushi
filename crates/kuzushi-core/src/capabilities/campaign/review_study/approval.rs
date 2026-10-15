use super::*;

pub(in crate::capabilities::campaign) fn approve_review_work(
    id: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<ApprovedWorkPlanV1>> {
    let root = ctx
        .workspace
        .context("review approval requires a workspace")?
        .root();
    let document = super::super::approved_work::read_bounded_plan(root, id)?;
    if document["kind"] != REVIEW_STUDY_KIND {
        return Ok(None);
    }
    let receipt = receipt_from_plan(id, &document)?;
    validate_approval(&receipt, input, ctx)?;
    Ok(Some(ApprovedWorkPlanV1 {
        schema_version: 1,
        campaign_id: id.into(),
        plan_sha256: receipt.plan_sha256,
        source_identity: receipt.source_identity,
        config_sha256: receipt.config_sha256,
        jobs: vec![ApprovedWorkItem {
            work_id: format!("{id}:{JOB}"),
            tool: TOOL.into(),
            input_sha256: work_input_digest(&receipt.input)?,
            max_attempts: 1,
        }],
    }))
}

fn validate_approval(
    receipt: &ReviewStudyReceipt,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    anyhow::ensure!(
        input["investigationId"] == receipt.investigation_id && input["model"] == receipt.model,
        "review investigation or selected model changed"
    );
    anyhow::ensure!(
        input["campaignPlanSha256"] == receipt.plan_sha256 && input["campaignJobs"] == 1,
        "review digest or job count changed"
    );
    anyhow::ensure!(
        input["maxJobAttempts"] == 1,
        "review permits one attempt; another review requires a new plan"
    );
    validate_current_selection(receipt, ctx)?;
    let root = ctx
        .workspace
        .context("review approval requires a workspace")?
        .root();
    anyhow::ensure!(
        crate::incremental_index::current_workspace_resume_identity(root)?
            == receipt.source_identity
            && crate::config_hash(ctx.config)? == receipt.config_sha256,
        "review source or configuration changed; prepare a new draft"
    );
    Ok(())
}

fn validate_current_selection(
    receipt: &ReviewStudyReceipt,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    let workspace = ctx
        .workspace
        .context("review approval requires a workspace")?;
    let owned = ctx
        .findings_store
        .is_none()
        .then(|| crate::FindingStore::open(workspace.findings_db_path()))
        .transpose()?;
    let bound = ToolExecutionContext {
        config: ctx.config,
        workspace: ctx.workspace,
        findings_store: ctx.findings_store.or(owned.as_ref()),
        trace: ctx.trace,
        cancellation: ctx.cancellation,
        authorization: ctx.authorization.clone(),
    };
    let (prepared, findings) = prepare_review(&receipt.input, &bound)?;
    anyhow::ensure!(
        prepared == receipt.input && findings == receipt.findings,
        "review selection or options changed; prepare a new draft"
    );
    Ok(())
}
