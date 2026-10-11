use super::*;
use crate::workspace::{load_accepted_scan_scope_proposal, ScanScopeReview};

pub(crate) fn compile_scope_study(
    input: &Value,
    draft: ScopeStudyDraft,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = ctx
        .workspace
        .context("Scope study requires an active repository")?
        .root();
    let review = load_accepted_scan_scope_proposal(ctx, &draft.proposal_ref)?;
    let registry = ModuleRegistry::with_v2_builtins();
    let common = freeze_common_input(input, ctx)?;
    let cases = freeze_cases(&draft, &review, &common, ctx, &registry)?;
    let unplanned_scope_ids = unplanned_scopes(&review, &cases);
    let metadata = ScopeStudyMetadataV1 {
        schema_version: 1,
        proposal_ref: draft.proposal_ref,
        selections: draft.cases,
        inherited_threat_model_ref: common["scanInput"]["threatModelRef"].clone(),
        cases,
        unplanned_scope_ids,
    };
    let id = input["campaignId"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| crate::new_run_id("study"));
    validate_scan_batch_id(&id)?;
    let mut plan = scope_document(root, &id, input, metadata, &registry, ctx)?;
    super::super::brief::attach(root, &mut plan, input)?;
    validate_scope_study_plan(&id, &plan)?;
    scan_cases::publish(root, &id, &plan)?;
    let receipt = load_scope_study_receipt(root, &id)?;
    let output = format!("Scope study draft: {} selected scopes · {} fixed discovery jobs · {} worker(s) · {} unplanned scopes. Review and approve this exact workload and shared allowance before starting. No jobs started.", receipt.scope_study.cases.len(), receipt.job_count, receipt.workers, receipt.scope_study.unplanned_scope_ids.len());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        serde_json::to_value(receipt)?,
    ))
}

fn freeze_common_input(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let mut common = input.clone();
    let scan = common
        .get_mut("scanInput")
        .context("scanInput is required")?;
    super::super::study_plan::bind_accepted_map_context(scan, ctx)?;
    let (frozen, _lease) = scan_cases::freeze_input(
        ctx.workspace
            .context("Scope study requires a repository")?
            .root(),
        scan,
    )?;
    *scan = frozen;
    Ok(common)
}

fn freeze_cases(
    draft: &ScopeStudyDraft,
    review: &ScanScopeReview,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Vec<FrozenContextCase>> {
    draft
        .cases
        .iter()
        .map(|case| freeze_case(case, draft, review, input, ctx, registry))
        .collect()
}

fn freeze_case(
    case: &ScopeStudyCaseInput,
    draft: &ScopeStudyDraft,
    review: &ScanScopeReview,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<FrozenContextCase> {
    let scope = review
        .record
        .draft
        .scopes
        .iter()
        .chain(review.record.draft.shared_scope.iter())
        .find(|scope| scope.id == case.scope_id)
        .context("Selected discovery scope is outside the accepted proposal")?;
    let base_input = prepare_scope_input(case, &draft.proposal_ref, input, ctx, registry)?;
    let root = ctx
        .workspace
        .context("Scope study requires a repository")?
        .root();
    let equivalence = capture_batch_equivalence(root, &base_input, ctx.config, registry)?;
    Ok(FrozenContextCase {
        id: case.scope_id.clone(),
        label: scope.name.clone(),
        passes: case.passes,
        base_input,
        equivalence,
        omission_scope_sha256: None,
    })
}

fn prepare_scope_input(
    case: &ScopeStudyCaseInput,
    proposal: &ScanScopeProposalRef,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Value> {
    let mut scan = input
        .get("scanInput")
        .cloned()
        .context("scanInput is required")?;
    scan.as_object_mut()
        .context("scanInput must be an object")?
        .insert(
            "scanScopeRef".into(),
            json!(ScanScopeRef {
                proposal: proposal.clone(),
                scope_id: case.scope_id.clone()
            }),
        );
    bind_scope_context(&mut scan, case, ctx)?;
    batch::equivalence::force_discovery_only(&mut scan)?;
    anyhow::ensure!(
        scan.get("allowanceRef").is_none(),
        "Approve the scope plan before attaching its allowance"
    );
    let prepared = registry.prepare_dispatch_input("sast:scan", scan, ctx, None)?;
    crate::modules::validate_study_scan_selection(prepared.value())?;
    let (frozen, _lease) = scan_cases::freeze_input(
        ctx.workspace
            .context("Scope study requires a repository")?
            .root(),
        prepared.value(),
    )?;
    Ok(frozen)
}

fn bind_scope_context(
    scan: &mut Value,
    case: &ScopeStudyCaseInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if let Some(reference) = &case.threat_model_ref {
        scan.as_object_mut().unwrap().remove("threat_model_ref");
        scan["threatModelRef"] = reference.clone();
    }
    super::super::study_plan::bind_accepted_map_context(scan, ctx)
}

fn unplanned_scopes(review: &ScanScopeReview, cases: &[FrozenContextCase]) -> Vec<String> {
    review
        .coverage
        .discovery_members
        .keys()
        .filter(|id| !cases.iter().any(|case| &case.id == *id))
        .cloned()
        .collect()
}

fn scope_document(
    root: &Path,
    id: &str,
    input: &Value,
    metadata: ScopeStudyMetadataV1,
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let first = metadata.first()?;
    let jobs = metadata
        .cases
        .iter()
        .flat_map(|case| {
            (1..=case.passes).map(move |trial| context_matrix::context_case_job(id, case, trial))
        })
        .collect::<Vec<_>>();
    let parallel = resolve_parallel_safety(
        registry,
        "sast:scan",
        &first.base_input,
        usize_input(input, &["workers"], 1),
    )?;
    let parallel = batch::limit_parallel_safety_to_jobs(parallel, jobs.len());
    let investigation = map_allowance::study_investigation(input, root, &first.base_input)?;
    let mut plan = json!({"schemaVersion":1,"kind":SCOPE_STUDY_KIND,"campaignId":id,"batchId":id,
        "tool":"sast:scan","requiresWorkApproval":true,"createdAtMs":batch::epoch_ms(),
        "workers":parallel.effective_workers,"requestedWorkers":parallel.requested_workers,"effectiveWorkers":parallel.effective_workers,
        "parallelSafety":parallel,"jobCount":jobs.len(),"jobs":jobs,"fillGaps":false,"coverageBypassed":true,
        "identityFold":first.base_input.get("identityFold"),"scopeStudy":metadata});
    if let Some(investigation) = investigation {
        plan["investigationId"] = json!(investigation);
    }
    super::super::study_resources::campaign_baseline::attach(
        ctx,
        input,
        &metadata.cases,
        &mut plan,
    )?;
    Ok(plan)
}
