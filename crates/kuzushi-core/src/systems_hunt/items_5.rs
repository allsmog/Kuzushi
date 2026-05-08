use super::prelude::*;
use super::*;

pub fn run_systems_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let target = resolve_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "systems-hunt: target is not a directory: {}",
            target.display()
        );
    }
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = gather_systems_context(&target, &options)?;
    if context.surfaces.is_empty() {
        return Ok(SystemsHuntReport {
            target: target.display().to_string(),
            count: 0,
            findings: Vec::new(),
            persisted: persist_systems_findings(&target, &[], ctx)?,
            artifacts: Vec::new(),
            cost_usd: 0.0,
        });
    }

    let runtime = runtime.context(
        "systems-hunt requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = resolve_model("systems-hunt", input, ctx, &options)?;
    let agent_tool_policy = agent_tool_policy_for_input(input)?;
    let invariants = query_systems_invariants(
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy.clone(),
    )?;
    let triggers = query_systems_triggers(
        runtime,
        &model,
        &target,
        &context,
        &invariants,
        &options,
        agent_tool_policy.clone(),
    )?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            SYSTEMS_HUNT_SYSTEM_PROMPT.to_string(),
            build_systems_hunt_prompt(&target, &context, &invariants, &triggers, &options)?,
        )
        .with_tool_policy(agent_tool_policy),
        StructuredJsonContract::new(
            "systems-hunt:systems-hunt",
            "SystemsHuntFindings",
            findings_schema(),
        ),
        require_json_object,
    )?;
    let artifact_root = artifact_root(&target, &options.artifact_dir)?;
    let (mut findings, artifacts) = normalize_systems_hunt_findings(
        raw,
        &target,
        &context,
        &artifact_root,
        options.max_findings,
    )?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }
    let persisted = persist_systems_findings(&target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    })
}

pub(crate) fn run_systems_invariant_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsInvariantOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = systems_context_from_input_or_gather(input, &target, &options)?;
    if systems_context_is_empty(&context) {
        return Ok(SystemsInvariantOutput {
            invariants: Vec::new(),
        });
    }
    let runtime = required_systems_runtime(runtime, "systems-hunt:systems-invariant-extract")?;
    let model = resolve_model(
        "systems-hunt:systems-invariant-extract",
        input,
        ctx,
        &options,
    )?;
    query_systems_invariants(
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy_for_input(input)?,
    )
}
