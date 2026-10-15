//! Shared authentication and dispatch shape for finite discovery cases.
use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use batch::equivalence::digest_serializable;
use serde_json::json;

pub(super) fn freeze_input(
    root: &Path,
    input: &Value,
) -> Result<(
    Value,
    crate::capabilities::threat_model::ThreatModelReadLease,
)> {
    let mut frozen = batch::scan_batch_base_input(input.clone());
    let lease = batch::acquire_plan_threat_model_lease(root, input)?;
    batch::bind_threat_model_ref(&mut frozen, lease.model_ref())?;
    crate::scan::freeze_scan_context(root, &mut frozen)?;
    crate::scan::freeze_threat_model_digest(root, &mut frozen, "sast:scan")?;
    Ok((frozen, lease))
}

pub(super) fn authenticate_case(case: &FrozenContextCase) -> Result<()> {
    let key = &case.equivalence;
    anyhow::ensure!(
        digest_serializable(&key.components)? == key.sha256,
        "Discovery case conditions are not authenticated"
    );
    anyhow::ensure!(
        digest_serializable(&case.base_input)? == key.components.prepared_input_sha256,
        "Discovery case input differs from its frozen receipt"
    );
    let selection =
        crate::capabilities::threat_model::ThreatModelSelection::from_input(&case.base_input)?;
    anyhow::ensure!(
        selection.is_bound(),
        "Discovery case needs an exact context revision or explicit omission"
    );
    anyhow::ensure!(
        &case.base_input["threatModelRef"]
            == key.components.threat_model.as_ref().unwrap_or(&Value::Null),
        "Discovery case context differs from its receipt"
    );
    for flag in ["triage", "verify", "autoPatch"] {
        anyhow::ensure!(
            case.base_input[flag] == json!(false),
            "Discovery case must freeze {flag}=false"
        );
    }
    Ok(())
}

pub(super) fn validate_jobs(id: &str, plan: &Value, cases: &[FrozenContextCase]) -> Result<()> {
    let jobs = cases
        .iter()
        .flat_map(|case| {
            (1..=case.passes).map(move |trial| context_matrix::context_case_job(id, case, trial))
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        plan["jobs"] == json!(jobs),
        "Discovery jobs differ from the frozen cases and repetitions"
    );
    anyhow::ensure!(
        required_usize(plan, "jobCount")? == jobs.len(),
        "Discovery job count differs from its frozen workload"
    );
    validate_workers(plan, jobs.len())
}

pub(super) fn validate_workers(plan: &Value, jobs: usize) -> Result<()> {
    let requested = required_usize(plan, "requestedWorkers")?;
    let effective = required_usize(plan, "effectiveWorkers")?;
    let receipt: ParallelSafetyResolution = serde_json::from_value(plan["parallelSafety"].clone())?;
    anyhow::ensure!(
        (1..=8).contains(&requested) && (1..=requested.min(jobs)).contains(&effective),
        "Discovery concurrency is outside its finite bounds"
    );
    anyhow::ensure!(
        receipt.requested_workers == requested && receipt.effective_workers == effective,
        "Worker receipt differs from frozen counts"
    );
    anyhow::ensure!(
        required_usize(plan, "workers")? == effective,
        "Discovery worker count changed"
    );
    Ok(())
}

pub(super) fn required_usize(plan: &Value, key: &str) -> Result<usize> {
    usize::try_from(
        plan[key]
            .as_u64()
            .with_context(|| format!("Study {key} is missing"))?,
    )
    .context("Study count is too large")
}

pub(super) fn publish(root: &Path, id: &str, plan: &Value) -> Result<()> {
    let path = campaign_plan_path(root, id);
    anyhow::ensure!(!path.exists(), "Study {id:?} already has an immutable plan");
    anyhow::ensure!(
        serde_json::to_vec(plan)?.len() <= 4 * 1024 * 1024,
        "Finite study exceeds the 4 MiB plan limit"
    );
    write_json_atomic(&path, plan)
}

pub(super) fn review_case(
    root: &Path,
    case: &FrozenContextCase,
    approval: &Value,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<()> {
    crate::scan::require_frozen_threat_model_digest(&case.base_input, "sast:scan")?;
    let prepared =
        registry.prepare_dispatch_input("sast:scan", case.base_input.clone(), ctx, None)?;
    let current = capture_batch_equivalence(root, prepared.value(), ctx.config, registry)?;
    anyhow::ensure!(
        current == case.equivalence,
        "Discovery case {} changed source, context, options or runtime; prepare a new plan",
        case.label
    );
    if let Some(model) = current.components.model {
        anyhow::ensure!(
            approval["model"] == json!(model),
            "Allowance model differs from the frozen discovery model"
        );
    }
    Ok(())
}
