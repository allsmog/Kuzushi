use super::*;

pub(crate) fn run_systems_invariant_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsInvariantOutput> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = systems_context_from_input_or_gather(input, &target, &options)?;
    if systems_context_is_empty(&context) {
        return Ok(empty_systems_invariants());
    }
    query_systems_invariants_for_context(input, ctx, runtime, target, context, options)
}

fn empty_systems_invariants() -> SystemsInvariantOutput {
    SystemsInvariantOutput {
        invariants: Vec::new(),
    }
}

fn query_systems_invariants_for_context(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    target: PathBuf,
    context: SystemsContextOutput,
    options: SystemsHuntInput,
) -> Result<SystemsInvariantOutput> {
    let runtime = required_systems_runtime(runtime, "systems-hunt:systems-invariant-extract")?;
    let request = systems_invariant_query_request(input, ctx, &options)?;
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", "systems-invariant-extract", "invariant-extract")
            .emit();
        trace.parent_scope(phase)
    });
    query_systems_invariants(
        runtime,
        &request.model,
        &target,
        &context,
        &options,
        request.tool_policy,
    )
}

struct SystemsInvariantQueryRequest {
    model: String,
    tool_policy: AgentToolPolicy,
}

fn systems_invariant_query_request(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    options: &SystemsHuntInput,
) -> Result<SystemsInvariantQueryRequest> {
    Ok(SystemsInvariantQueryRequest {
        model: systems_invariant_model(input, ctx, options)?,
        tool_policy: agent_tool_policy_for_input(input)?,
    })
}

fn systems_invariant_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    options: &SystemsHuntInput,
) -> Result<String> {
    resolve_model(
        "systems-hunt:systems-invariant-extract",
        input,
        ctx,
        options,
    )
}
