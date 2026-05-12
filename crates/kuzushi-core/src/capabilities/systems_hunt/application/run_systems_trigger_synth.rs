use super::*;

pub(crate) fn run_systems_trigger_synth(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsTriggerOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = systems_context_from_input_or_gather(input, &target, &options)?;
    if systems_context_is_empty(&context) {
        return Ok(SystemsTriggerOutput {
            triggers: Vec::new(),
        });
    }
    let runtime = required_systems_runtime(runtime, "systems-hunt:systems-trigger-synth")?;
    let model = resolve_model("systems-hunt:systems-trigger-synth", input, ctx, &options)?;
    let agent_tool_policy = default_whitebox_static_agent_tool_policy();
    let thinking_level = agentic_hunter_thinking_level(input);
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                "systems-trigger-synth",
                "invariant + trigger synthesis",
            )
            .emit();
        trace.parent_scope(phase)
    });
    let invariant_output = systems_invariants_from_input_or_query(
        input,
        runtime,
        &model,
        &target,
        &context,
        &options,
        agent_tool_policy.clone(),
        &thinking_level,
    )?;
    let result = query_systems_triggers(
        runtime,
        &model,
        &target,
        &context,
        &invariant_output,
        &options,
        agent_tool_policy,
        &thinking_level,
    );
    drop(_llm_scope);
    result
}

pub(crate) fn systems_context_from_input_or_gather(
    input: &Value,
    target: &Path,
    options: &SystemsHuntInput,
) -> Result<SystemsContextOutput> {
    Ok(context_from_input(input).transpose()?.unwrap_or_else(|| {
        gather_systems_context(target, options).unwrap_or_else(|_| empty_context())
    }))
}

pub(crate) fn systems_context_is_empty(context: &SystemsContextOutput) -> bool {
    context.surfaces.is_empty()
}

pub(crate) fn required_systems_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
    tool: &str,
) -> Result<&'a dyn AgentRuntime> {
    runtime.with_context(|| format!(
        "{tool} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))
}

pub(crate) fn systems_invariants_from_input_or_query(
    input: &Value,
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &str,
) -> Result<SystemsInvariantOutput> {
    match invariants_from_input(input).transpose()? {
        Some(output) => Ok(output),
        None => query_systems_invariants(
            runtime,
            model,
            target,
            context,
            options,
            agent_tool_policy,
            thinking_level,
        ),
    }
}
