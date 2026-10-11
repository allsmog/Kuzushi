use super::*;
use batch::equivalence::digest_serializable;

pub fn validate_scope_study_plan(id: &str, plan: &Value) -> Result<ScopeStudyMetadataV1> {
    validate_header(id, plan)?;
    let metadata: ScopeStudyMetadataV1 = serde_json::from_value(plan["scopeStudy"].clone())
        .context("Scope study metadata is malformed")?;
    validate_cases(&metadata)?;
    super::super::study_resources::campaign_preview::from_plan(plan, &metadata.cases)?;
    scan_cases::validate_jobs(id, plan, &metadata.cases)?;
    Ok(metadata)
}

fn validate_header(id: &str, plan: &Value) -> Result<()> {
    validate_scan_batch_id(id)?;
    anyhow::ensure!(
        plan["schemaVersion"] == json!(1) && plan["kind"] == json!(SCOPE_STUDY_KIND),
        "Unsupported scope study format"
    );
    anyhow::ensure!(
        plan["campaignId"] == json!(id) && plan["batchId"] == json!(id),
        "Scope study id differs from its path"
    );
    anyhow::ensure!(
        plan["tool"] == json!("sast:scan") && plan["requiresWorkApproval"] == json!(true),
        "Scope study requires explicit discovery work approval"
    );
    anyhow::ensure!(
        plan["fillGaps"] == json!(false) && plan["coverageBypassed"] == json!(true),
        "Scope study cannot create gap-filling work"
    );
    Ok(())
}

fn validate_cases(metadata: &ScopeStudyMetadataV1) -> Result<()> {
    anyhow::ensure!(
        metadata.schema_version == 1,
        "Unsupported scope study schema"
    );
    let draft = ScopeStudyDraft {
        proposal_ref: metadata.proposal_ref.clone(),
        cases: metadata.selections.clone(),
    };
    draft.validate()?;
    validate_selections(metadata)?;
    let first = metadata.first()?;
    for case in &metadata.cases {
        scan_cases::authenticate_case(case)?;
        validate_scope_binding(case, metadata)?;
        validate_controlled_conditions(first, case)?;
    }
    Ok(())
}

fn validate_selections(metadata: &ScopeStudyMetadataV1) -> Result<()> {
    anyhow::ensure!(
        metadata.cases.len() == metadata.selections.len(),
        "Scope selections differ from frozen cases"
    );
    for (case, selected) in metadata.cases.iter().zip(&metadata.selections) {
        anyhow::ensure!(
            !case.label.trim().is_empty()
                && case.label.len() <= 160
                && !case.label.chars().any(char::is_control),
            "Invalid frozen scope label"
        );
        anyhow::ensure!(
            case.id == selected.scope_id && case.passes == selected.passes,
            "Scope case differs from the selected boundary or pass count"
        );
        let expected = selected
            .threat_model_ref
            .as_ref()
            .unwrap_or(&metadata.inherited_threat_model_ref);
        anyhow::ensure!(
            &case.base_input["threatModelRef"] == expected,
            "Scope context differs from its frozen inheritance or explicit override"
        );
    }
    Ok(())
}

fn validate_scope_binding(case: &FrozenContextCase, metadata: &ScopeStudyMetadataV1) -> Result<()> {
    let reference: ScanScopeRef = serde_json::from_value(case.base_input["scanScopeRef"].clone())?;
    anyhow::ensure!(
        reference.proposal == metadata.proposal_ref && reference.scope_id == case.id,
        "Discovery case differs from its accepted scope reference"
    );
    crate::modules::validate_scan_scope_contract(&case.base_input)
}

fn validate_controlled_conditions(
    first: &FrozenContextCase,
    case: &FrozenContextCase,
) -> Result<()> {
    let mut left = first.equivalence.components.clone();
    let mut right = case.equivalence.components.clone();
    for key in [&mut left, &mut right] {
        key.prepared_input_sha256.clear();
        key.scope_sha256.clear();
        key.threat_model = None;
    }
    anyhow::ensure!(
        left == right,
        "Scope cases changed source, model, runtime, engine, prompts or common configuration"
    );
    anyhow::ensure!(
        common_input(&first.base_input)? == common_input(&case.base_input)?,
        "Scope cases may change only accepted scope and explicit context selection"
    );
    Ok(())
}

fn common_input(input: &Value) -> Result<Value> {
    let mut input = input.clone();
    let object = input
        .as_object_mut()
        .context("Scope case input must be an object")?;
    object.remove("scanScopeRef");
    object.remove("threatModelRef");
    Ok(input)
}

pub fn load_scope_study_receipt(root: &Path, id: &str) -> Result<ScopeStudyReceipt> {
    let plan = approved_work::read_bounded_plan(root, id)?;
    let scope_study = validate_scope_study_plan(id, &plan)?;
    let resource_evidence =
        super::super::study_resources::campaign_preview::from_plan(&plan, &scope_study.cases)?;
    let supporting_context =
        crate::scan::inspect_scan_context(root, &scope_study.first()?.base_input)?;
    Ok(ScopeStudyReceipt {
        schema_version: 1,
        kind: SCOPE_STUDY_KIND.into(),
        campaign_id: id.into(),
        investigation_id: plan["investigationId"].as_str().map(str::to_owned),
        plan_path: campaign_plan_path(root, id),
        plan_sha256: digest_serializable(&plan)?,
        workers: scan_cases::required_usize(&plan, "effectiveWorkers")?,
        requested_workers: scan_cases::required_usize(&plan, "requestedWorkers")?,
        worker_limitation: plan
            .pointer("/parallelSafety/clampReason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        job_count: scan_cases::required_usize(&plan, "jobCount")?,
        scope_study,
        supporting_context,
        resource_evidence: resource_evidence,
    })
}

pub(in crate::capabilities::campaign) fn review_for_approval(
    root: &Path,
    id: &str,
    plan: &Value,
    approval: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Option<BatchEquivalenceKey>> {
    if plan["kind"] != json!(SCOPE_STUDY_KIND) {
        return Ok(None);
    }
    let metadata = validate_scope_study_plan(id, plan)?;
    let accepted =
        crate::workspace::load_accepted_scan_scope_proposal(ctx, &metadata.proposal_ref)?;
    let expected = accepted
        .coverage
        .discovery_members
        .keys()
        .filter(|id| !metadata.cases.iter().any(|case| &case.id == *id))
        .cloned()
        .collect::<Vec<_>>();
    anyhow::ensure!(
        metadata.unplanned_scope_ids == expected,
        "Unplanned boundaries differ from the accepted proposal"
    );
    anyhow::ensure!(
        approval["campaignJobs"] == plan["jobCount"],
        "Approved work differs from the scope study's fixed jobs"
    );
    for case in &metadata.cases {
        scan_cases::review_case(root, case, approval, ctx, registry)?;
    }
    Ok(Some(metadata.first()?.equivalence.clone()))
}
