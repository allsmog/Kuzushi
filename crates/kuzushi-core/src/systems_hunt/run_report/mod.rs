use super::*;

mod invariant_extract;
pub(crate) use invariant_extract::run_systems_invariant_extract;

pub fn run_systems_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsHuntReport> {
    let target = systems_hunt_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = gather_systems_context(&target, &options)?;
    if context.surfaces.is_empty() {
        return empty_systems_hunt_report(&target, ctx);
    }

    let runtime = required_systems_runtime(runtime, "systems-hunt")?;
    let model = resolve_model("systems-hunt", input, ctx, &options)?;
    let agent_tool_policy = agent_tool_policy_for_input(input)?;
    // Phase scope: invariants + triggers + final hunt are three sequential
    // LLM rounds; group them under a single header in the verbose feed.
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "systems-hunt", "invariants · triggers · hunt")
            .emit();
        trace.parent_scope(phase)
    });
    let raw = query_systems_hunt_findings(
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy,
    )?;
    drop(_llm_scope);
    finalize_systems_hunt_report(raw, input, ctx, &target, &context, &options)
}

fn systems_hunt_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let target = resolve_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "systems-hunt: target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

fn finalize_systems_hunt_report(
    raw: Value,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
) -> Result<SystemsHuntReport> {
    let artifact_root = artifact_root(target, &options.artifact_dir)?;
    let (mut findings, artifacts) = normalize_systems_hunt_findings(
        raw,
        target,
        context,
        &artifact_root,
        options.max_findings,
    )?;
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }
    let persisted = persist_systems_findings(target, &findings, ctx)?;

    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        artifacts,
        cost_usd: 0.0,
    })
}

fn empty_systems_hunt_report(
    target: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<SystemsHuntReport> {
    Ok(SystemsHuntReport {
        target: target.display().to_string(),
        count: 0,
        findings: Vec::new(),
        persisted: persist_systems_findings(target, &[], ctx)?,
        artifacts: Vec::new(),
        cost_usd: 0.0,
    })
}

fn query_systems_hunt_findings(
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
) -> Result<Value> {
    let invariants = query_systems_invariants(
        runtime,
        model,
        target,
        context,
        options,
        agent_tool_policy.clone(),
    )?;
    let triggers = query_systems_triggers(
        runtime,
        model,
        target,
        context,
        &invariants,
        options,
        agent_tool_policy.clone(),
    )?;
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            target.to_path_buf(),
            SYSTEMS_HUNT_SYSTEM_PROMPT.to_string(),
            build_systems_hunt_prompt(target, context, &invariants, &triggers, options)?,
        )
        .with_tool_policy(agent_tool_policy),
        StructuredJsonContract::new(
            "systems-hunt:systems-hunt",
            "SystemsHuntFindings",
            findings_schema(),
        ),
        require_json_object,
    )
}
