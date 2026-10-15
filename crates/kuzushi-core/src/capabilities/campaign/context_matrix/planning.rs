use super::*;
use batch::equivalence::force_discovery_only;

pub(crate) fn compile_context_matrix(
    input: &Value,
    draft: ContextMatrixDraft,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let root = ctx
        .workspace
        .context("Context matrix requires a workspace")?
        .root();
    let id = input["campaignId"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| crate::new_run_id("study"));
    validate_matrix_id(&id)?;
    let registry = ModuleRegistry::with_v2_builtins();
    let cases = freeze_cases(root, &draft, input, ctx, &registry)?;
    let metadata = ContextMatrixMetadataV1 {
        schema_version: 1,
        baseline_case_id: draft.baseline_case_id,
        cases,
    };
    let mut plan = matrix_document(root, &id, input, metadata, &registry, ctx)?;
    super::super::brief::attach(root, &mut plan, input)?;
    validate_context_matrix_plan(&id, &plan)?;
    super::super::scan_cases::publish(root, &id, &plan)?;
    let receipt = load_context_matrix_receipt(root, &id)?;
    let output = format!("Context matrix draft: {} cases · {} fixed discovery jobs · {} worker(s). Review and approve this entire plan and its shared allowance before starting. No jobs started.",
        receipt.matrix.cases.len(), receipt.job_count, receipt.workers);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        serde_json::to_value(receipt)?,
    ))
}

fn validate_matrix_id(id: &str) -> Result<()> {
    validate_scan_batch_id(id)?;
    anyhow::ensure!(id.len() <= 64, "Context matrix id exceeds 64 characters");
    Ok(())
}

fn freeze_cases(
    root: &Path,
    draft: &ContextMatrixDraft,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Vec<FrozenContextCase>> {
    let mut cases = Vec::new();
    for case in &draft.cases {
        let base_input = prepare_case_input(case, input, ctx, registry)?;
        let equivalence = capture_batch_equivalence(root, &base_input, ctx.config, registry)?;
        let omission_scope_sha256 = scope_comparison::capture_omission_scope(root, &base_input)?;
        cases.push(FrozenContextCase {
            id: case.id.clone(),
            label: case.label.clone(),
            passes: case.passes,
            base_input,
            equivalence,
            omission_scope_sha256,
        });
    }
    Ok(cases)
}

fn prepare_case_input(
    case: &ContextCaseInput,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Value> {
    let mut scan_input = input
        .get("scanInput")
        .cloned()
        .context("scanInput is required")?;
    let object = scan_input
        .as_object_mut()
        .context("scanInput must be an object")?;
    anyhow::ensure!(!object.contains_key("threatModelRef") && !object.contains_key("threat_model_ref"), "Context matrix bindings belong in contextCases; remove the duplicate scanInput context selection");
    object.insert("threatModelRef".into(), case.threat_model_ref.clone());
    object.remove("threatModelDigestRef");
    force_discovery_only(&mut scan_input)?;
    anyhow::ensure!(
        scan_input.get("allowanceRef").is_none(),
        "Approve the matrix plan before attaching its allowance"
    );
    let prepared = registry.prepare_dispatch_input("sast:scan", scan_input, ctx, None)?;
    crate::modules::validate_study_scan_selection(prepared.value())?;
    let mut frozen = prepared.value().clone();
    crate::scan::freeze_scan_context(
        ctx.workspace
            .context("Context matrix requires a workspace")?
            .root(),
        &mut frozen,
    )?;
    crate::scan::freeze_threat_model_digest(
        ctx.workspace
            .context("Context matrix requires a workspace")?
            .root(),
        &mut frozen,
        "sast:scan",
    )?;
    Ok(frozen)
}

fn matrix_document(
    root: &Path,
    id: &str,
    input: &Value,
    metadata: ContextMatrixMetadataV1,
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let baseline = metadata.baseline()?;
    let workers = usize_input(input, &["workers"], 1);
    let parallel = resolve_parallel_safety(registry, "sast:scan", &baseline.base_input, workers)?;
    let investigation = map_allowance::study_investigation(input, root, &baseline.base_input)?;
    let jobs = metadata
        .cases
        .iter()
        .flat_map(|case| (1..=case.passes).map(move |trial| context_case_job(id, case, trial)))
        .collect::<Vec<_>>();
    let parallel = batch::limit_parallel_safety_to_jobs(parallel, jobs.len());
    let mut plan = json!({"schemaVersion":1,"kind":CONTEXT_MATRIX_KIND,"campaignId":id,"batchId":id,
        "tool":"sast:scan","requiresWorkApproval":true,
        "createdAtMs":batch::epoch_ms(),"workers":parallel.effective_workers,
        "requestedWorkers":parallel.requested_workers,"effectiveWorkers":parallel.effective_workers,
        "parallelSafety":parallel,"jobCount":jobs.len(),"jobs":jobs,
        "fillGaps":false,"coverageBypassed":true,"identityFold":baseline.base_input.get("identityFold"),
        "contextMatrix":metadata});
    bind_matrix_metadata(root, &mut plan, input, investigation)?;
    super::super::study_resources::campaign_baseline::attach(
        ctx,
        input,
        &metadata.cases,
        &mut plan,
    )?;
    Ok(plan)
}

fn bind_matrix_metadata(
    root: &Path,
    plan: &mut Value,
    input: &Value,
    investigation: Option<String>,
) -> Result<()> {
    if let Some(id) = investigation {
        validate_scan_batch_id(&id)?;
        plan["investigationId"] = json!(id);
    }
    if let Some(run) = input.get("baselineRunId") {
        let id = run.as_str().context("baselineRunId must be a string")?;
        crate::run_artifacts::resolve_run_artifact_path(root, id, "run.json")?;
        plan["resourceBaselineRunId"] = run.clone();
    }
    Ok(())
}
