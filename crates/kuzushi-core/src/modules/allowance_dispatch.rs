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
        && descriptor_work(tool).is_some()
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

fn descriptor_work(tool: &ToolDescriptor) -> Option<InvestigationWork> {
    let Some(category) = tool.allowance_category else {
        return phase_work(tool.phase);
    };
    Some(match category {
        AllowanceCategory::Context => InvestigationWork::Context,
        AllowanceCategory::Scope => InvestigationWork::Scope,
        AllowanceCategory::Discovery => InvestigationWork::Discovery,
        AllowanceCategory::Review => InvestigationWork::Review,
        AllowanceCategory::Report => InvestigationWork::Report,
        AllowanceCategory::Learning => InvestigationWork::Learning,
    })
}

pub(super) fn validate_reference(input: &Value) -> Result<()> {
    reference(input).map(|_| ())
}

pub(super) fn validate_tool_reference(descriptor: &ToolDescriptor, input: &Value) -> Result<()> {
    validate_reference(input)?;
    require_model_ranking_reference(descriptor, input)
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
    require_context_plan_reference(descriptor, input)?;
    require_model_ranking_reference(descriptor, input)?;
    let Some(reference) = reference(input)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        supports_allowance(descriptor),
        "tool does not support an investigation allowance"
    );
    let ledger = open_ledger(ctx)?;
    let snapshot = ledger.allowance_snapshot(&reference.investigation_id)?;
    require_fixed_context_work(descriptor, input, &snapshot)?;
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
    require_selected_runtime_capacity(descriptor, input, ctx, &snapshot)?;
    let binding = runtime_binding(descriptor, input, ctx, reference, ledger)?;
    runtime.with_allowance_binding(binding).map(Some)
}

fn require_model_ranking_reference(descriptor: &ToolDescriptor, input: &Value) -> Result<()> {
    if descriptor.name == "module-recommender:recommend"
        && crate::capabilities::module_recommender::model_ranking_enabled(input)
    {
        anyhow::ensure!(input.get(OPTION).is_some(), "Model ranking requires an explicitly approved allowanceRef; deterministic ranking uses no model request");
    }
    Ok(())
}

fn requires_fixed_context_plan(descriptor: &ToolDescriptor, input: &Value) -> bool {
    descriptor.name == "threat-model:build"
        && (input.get("scanScopeRef").is_some() || input.get("operatorBriefRef").is_some())
}

fn require_context_plan_reference(descriptor: &ToolDescriptor, input: &Value) -> Result<()> {
    if requires_fixed_context_plan(descriptor, input) {
        anyhow::ensure!(input.get(OPTION).is_some(), "Context generation with file groups or goal guidance requires an explicit allowanceRef from its approved context study");
    }
    Ok(())
}

fn require_fixed_context_work(
    descriptor: &ToolDescriptor,
    input: &Value,
    snapshot: &crate::allowance::AllowanceSnapshot,
) -> Result<()> {
    if requires_fixed_context_plan(descriptor, input) {
        anyhow::ensure!(
            snapshot.work_plan.is_some(),
            "Context generation with file groups or goal guidance requires an approved fixed context plan"
        );
    }
    Ok(())
}

fn require_selected_runtime_capacity(
    descriptor: &ToolDescriptor,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    snapshot: &crate::allowance::AllowanceSnapshot,
) -> Result<()> {
    if !super::runtime_requirements::tool_wants_runtime(&descriptor.name, input, ctx.config) {
        return Ok(());
    }
    snapshot.require_call_capacity(
        descriptor_work(descriptor).context("tool has no investigation work category")?,
    )
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
        work: descriptor_work(descriptor).context("tool has no investigation work category")?,
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
