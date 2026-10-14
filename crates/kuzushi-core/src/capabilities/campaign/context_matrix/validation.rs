//! Authenticate the complete frozen matrix before reviewing or dispatching it.
use super::*;
use batch::equivalence::digest_serializable;

pub fn load_context_matrix_receipt(root: &Path, id: &str) -> Result<ContextMatrixReceipt> {
    let plan = approved_work::read_bounded_plan(root, id)?;
    let matrix = validate_context_matrix_plan(id, &plan)?;
    let resource_evidence =
        super::super::study_resources::campaign_preview::from_plan(&plan, &matrix.cases)?;
    Ok(ContextMatrixReceipt {
        schema_version: 1,
        campaign_id: id.into(),
        investigation_id: plan["investigationId"].as_str().map(str::to_owned),
        plan_path: campaign_plan_path(root, id),
        plan_sha256: digest_serializable(&plan)?,
        workers: required_usize(&plan, "effectiveWorkers")?,
        requested_workers: required_usize(&plan, "requestedWorkers")?,
        worker_limitation: plan
            .pointer("/parallelSafety/clampReason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        job_count: required_usize(&plan, "jobCount")?,
        supporting_context: crate::scan::inspect_scan_context(
            root,
            &matrix.baseline()?.base_input,
        )?,
        matrix,
        resource_evidence,
    })
}

pub fn validate_context_matrix_plan(id: &str, plan: &Value) -> Result<ContextMatrixMetadataV1> {
    validate_header(id, plan)?;
    let matrix: ContextMatrixMetadataV1 = serde_json::from_value(plan["contextMatrix"].clone())
        .context("Context matrix metadata is malformed")?;
    validate_cases(&matrix)?;
    super::super::study_resources::campaign_preview::from_plan(plan, &matrix.cases)?;
    validate_jobs(id, plan, &matrix)?;
    validate_workers(plan, matrix.cases.iter().map(|case| case.passes).sum())?;
    Ok(matrix)
}

fn validate_header(id: &str, plan: &Value) -> Result<()> {
    validate_scan_batch_id(id)?;
    anyhow::ensure!(
        plan["schemaVersion"] == json!(1) && plan["kind"] == json!(CONTEXT_MATRIX_KIND),
        "Unsupported context matrix format"
    );
    anyhow::ensure!(
        plan["campaignId"] == json!(id) && plan["batchId"] == json!(id),
        "Context matrix id differs from its path"
    );
    anyhow::ensure!(
        plan["tool"] == json!("sast:scan") && plan["requiresWorkApproval"] == json!(true),
        "Context matrix needs explicit discovery work approval"
    );
    anyhow::ensure!(
        plan["fillGaps"] == json!(false) && plan["coverageBypassed"] == json!(true),
        "Context matrix cannot create gap-filling work"
    );
    Ok(())
}

fn validate_cases(matrix: &ContextMatrixMetadataV1) -> Result<()> {
    anyhow::ensure!(
        matrix.schema_version == 1,
        "Unsupported context case schema"
    );
    let draft = ContextMatrixDraft {
        baseline_case_id: matrix.baseline_case_id.clone(),
        cases: matrix
            .cases
            .iter()
            .map(|case| ContextCaseInput {
                id: case.id.clone(),
                label: case.label.clone(),
                passes: case.passes,
                threat_model_ref: case.base_input["threatModelRef"].clone(),
            })
            .collect(),
    };
    draft.validate()?;
    let baseline = matrix.baseline()?;
    for case in &matrix.cases {
        authenticate_case(case)?;
        validate_controlled_conditions(baseline, case)?;
    }
    Ok(())
}

fn authenticate_case(case: &FrozenContextCase) -> Result<()> {
    let key = &case.equivalence;
    anyhow::ensure!(
        digest_serializable(&key.components)? == key.sha256,
        "Context case conditions are not authenticated"
    );
    anyhow::ensure!(
        digest_serializable(&case.base_input)? == key.components.prepared_input_sha256,
        "Context case input differs from its condition receipt"
    );
    let selection =
        crate::capabilities::threat_model::ThreatModelSelection::from_input(&case.base_input)?;
    anyhow::ensure!(
        selection.is_bound(),
        "Context case needs an exact revision or explicit omission"
    );
    let captured = key.components.threat_model.as_ref().unwrap_or(&Value::Null);
    anyhow::ensure!(
        &case.base_input["threatModelRef"] == captured,
        "Context case input differs from its recorded context"
    );
    validate_discovery_flags(&case.base_input)
}

fn validate_discovery_flags(input: &Value) -> Result<()> {
    for key in ["triage", "verify", "autoPatch"] {
        anyhow::ensure!(
            input[key] == json!(false),
            "Context cases must freeze {key}=false"
        );
    }
    Ok(())
}

fn validate_controlled_conditions(
    baseline: &FrozenContextCase,
    case: &FrozenContextCase,
) -> Result<()> {
    scope_comparison::require_case_conditions(baseline, case)
}

fn validate_jobs(id: &str, plan: &Value, matrix: &ContextMatrixMetadataV1) -> Result<()> {
    let expected = matrix
        .cases
        .iter()
        .flat_map(|case| (1..=case.passes).map(move |trial| context_case_job(id, case, trial)))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        plan["jobs"] == json!(expected),
        "Context matrix jobs differ from its finite cases and repetitions"
    );
    anyhow::ensure!(
        required_usize(plan, "jobCount")? == expected.len(),
        "Context matrix job count differs from its frozen work"
    );
    Ok(())
}

fn validate_workers(plan: &Value, jobs: usize) -> Result<()> {
    let requested = required_usize(plan, "requestedWorkers")?;
    let effective = required_usize(plan, "effectiveWorkers")?;
    let receipt: ParallelSafetyResolution = serde_json::from_value(plan["parallelSafety"].clone())?;
    anyhow::ensure!(
        (1..=8).contains(&requested) && (1..=requested.min(jobs)).contains(&effective),
        "Context matrix concurrency is outside its finite bounds"
    );
    anyhow::ensure!(
        receipt.requested_workers == requested && receipt.effective_workers == effective,
        "Context matrix worker receipt differs from its frozen counts"
    );
    anyhow::ensure!(
        required_usize(plan, "workers")? == effective,
        "Context matrix worker count changed"
    );
    Ok(())
}

fn required_usize(plan: &Value, key: &str) -> Result<usize> {
    usize::try_from(
        plan[key]
            .as_u64()
            .with_context(|| format!("Context matrix {key} is missing"))?,
    )
    .context("Context matrix count is too large")
}
