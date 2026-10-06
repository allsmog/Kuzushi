//! Descriptor-owned allowance attribution shared by scan, shell and run.
use super::*;
use crate::allowance::{AllowanceBinding, AllowanceReferenceV1, AllowanceWork, InvestigationWork};
use std::sync::Arc;

const OPTION: &str = "allowanceRef";

pub(super) fn declare_allowance_option(mut tool: ToolDescriptor) -> ToolDescriptor {
    if supports_allowance(&tool) && !tool.options.iter().any(|option| option.name == OPTION) {
        tool.options.push(opt(
            OPTION,
            OptionType::Json,
            "Approved call allowance reference: schemaVersion=1, investigationId, revision and workId. Does not approve or start extra work. Dollar cost may be unavailable.",
        ).advanced());
    }
    tool
}

fn supports_allowance(tool: &ToolDescriptor) -> bool {
    matches!(tool.effect, ToolEffect::Read | ToolEffect::WorkspaceWrite)
        && phase_work(tool.phase).is_some()
}

fn phase_work(phase: ToolPhase) -> Option<InvestigationWork> {
    match phase {
        ToolPhase::Map => Some(InvestigationWork::Context),
        ToolPhase::Scan => Some(InvestigationWork::Discovery),
        ToolPhase::Review => Some(InvestigationWork::Review),
        ToolPhase::Report => Some(InvestigationWork::Report),
        _ => None,
    }
}

pub(super) fn validate_reference(input: &Value) -> Result<()> {
    reference(input).map(|_| ())
}

fn reference(input: &Value) -> Result<Option<AllowanceReferenceV1>> {
    let Some(value) = input.get(OPTION) else {
        return Ok(None);
    };
    let reference: AllowanceReferenceV1 = serde_json::from_value(value.clone())
        .context("allowanceRef must name an approved investigation revision and work item")?;
    reference.validate()?;
    Ok(Some(reference))
}

pub(super) fn bind_runtime<'a>(
    descriptor: &ToolDescriptor,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<Option<Box<dyn AgentRuntime + 'a>>> {
    bind_selected_runtime(descriptor, input, ctx, runtime).map_err(refused)
}

fn refused(error: anyhow::Error) -> anyhow::Error {
    if crate::runtime::runtime_failure_metadata(&error).is_some() {
        return error;
    }
    anyhow::Error::new(crate::RuntimeFailure::new(
        crate::RuntimeFailureMetadata::new(
            crate::RuntimeFailureClass::AllowanceRefused,
            None,
            None,
        ),
    ))
    .context(error)
}

fn bind_selected_runtime<'a>(
    descriptor: &ToolDescriptor,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<Option<Box<dyn AgentRuntime + 'a>>> {
    if descriptor.name == "sast:scan" {
        crate::capabilities::campaign::require_study_reference(input, ctx)?;
    }
    let Some(reference) = reference(input)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        supports_allowance(descriptor),
        "tool does not support an investigation allowance"
    );
    let ledger = open_ledger(ctx)?;
    let snapshot = ledger.allowance_snapshot(&reference.investigation_id)?;
    anyhow::ensure!(
        snapshot.revision == reference.revision,
        "allowance revision changed; review remaining work"
    );
    if let Some(plan) = &snapshot.work_plan {
        plan.job(&reference.work_id)?;
        anyhow::ensure!(
            ctx.run_id().is_some(),
            "approved work requires a durable run identity"
        );
    }
    let Some(runtime) = runtime else {
        return Ok(None);
    };
    let binding = runtime_binding(descriptor, input, ctx, reference, ledger)?;
    runtime.with_allowance_binding(binding).map(Some)
}

fn runtime_binding(
    descriptor: &ToolDescriptor,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    reference: AllowanceReferenceV1,
    ledger: Arc<crate::SpendLimiter>,
) -> Result<AllowanceBinding> {
    let work = AllowanceWork {
        investigation_id: reference.investigation_id,
        revision: reference.revision,
        work_id: reference.work_id,
        run_id: ctx
            .run_id()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        model: resolve_tool_model(&descriptor.name, input, ctx)?,
        work: phase_work(descriptor.phase).context("tool has no investigation work category")?,
    };
    AllowanceBinding::new(ledger, work)
}

pub(super) fn open_ledger(ctx: &ToolExecutionContext<'_>) -> Result<Arc<crate::SpendLimiter>> {
    let workspace = ctx
        .workspace
        .context("investigation allowance requires an active workspace")?;
    crate::SpendLimiter::open(workspace.findings_db_path()).map(Arc::new)
}

/// Claim only after authorization and preflight, before any executor starts.
pub(super) fn claim_work(input: &Value, name: &str, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    claim_selected_work(input, name, ctx).map_err(refused)
}

fn claim_selected_work(input: &Value, name: &str, ctx: &ToolExecutionContext<'_>) -> Result<()> {
    let Some(reference) = reference(input)? else {
        return Ok(());
    };
    let ledger = open_ledger(ctx)?;
    if ledger
        .allowance_snapshot(&reference.investigation_id)?
        .work_plan
        .is_none()
    {
        return Ok(());
    }
    let root = ctx
        .workspace
        .context("approved work requires a workspace")?
        .root();
    ledger.claim_work_attempt(&crate::allowance::WorkAttempt {
        reference: &reference,
        run_id: &ctx
            .run_id()
            .context("approved work requires a durable run identity")?,
        tool: name,
        input_sha256: &crate::capabilities::campaign::work_input_digest(input)?,
        source_identity: &crate::incremental_index::current_workspace_resume_identity(root)?,
        config_sha256: &crate::config_hash(ctx.config)?,
    })
}

/// Keep governance input out of engine-specific parsers and model prompts.
pub(super) fn executor_input(input: &Value) -> std::borrow::Cow<'_, Value> {
    if input.get(OPTION).is_none() {
        return std::borrow::Cow::Borrowed(input);
    }
    let mut input = input.clone();
    if let Some(object) = input.as_object_mut() {
        object.remove(OPTION);
    }
    std::borrow::Cow::Owned(input)
}

/// Only prepared dispatch may attribute a result to investigation accounting.
/// Engines cannot supply this receipt, even when no allowance was selected.
pub(super) fn attach_result_reference(input: &Value, output: &mut Value) -> Result<()> {
    let Some(object) = output.as_object_mut() else {
        return Ok(());
    };
    object.remove(OPTION);
    if let Some(reference) = reference(input)? {
        object.insert(OPTION.into(), serde_json::to_value(reference)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod work_tests;
