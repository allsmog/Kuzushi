use super::*;

#[cfg(test)]
pub(crate) fn run_systems_invariant_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsInvariantOutput> {
    Ok(run_systems_invariant_extract_with_cost(input, ctx, runtime)?.value)
}

pub(crate) fn run_systems_invariant_extract_with_cost(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<CostedStructuredJson<SystemsInvariantOutput>> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = systems_context_from_input_or_gather(input, &target, &options)?;
    if systems_context_is_empty(&context) {
        return Ok(CostedStructuredJson::from_cost_report(
            empty_systems_invariants(),
            crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
        ));
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
) -> Result<CostedStructuredJson<SystemsInvariantOutput>> {
    let runtime = required_systems_runtime(runtime, "systems-hunt:systems-invariant-extract")?;
    let request = systems_invariant_query_request(input, ctx, &options, &target)?;
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                "systems-invariant-extract",
                "invariant-extract",
            )
            .emit();
        trace.parent_scope(phase)
    });
    query_systems_invariants_with_cost(
        runtime,
        &request.model,
        &target,
        &context,
        &options,
        request.tool_policy,
        &request.thinking_level,
    )
}

struct SystemsInvariantQueryRequest {
    model: String,
    tool_policy: AgentToolPolicy,
    thinking_level: String,
}

fn systems_invariant_query_request(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    options: &SystemsHuntInput,
    target: &Path,
) -> Result<SystemsInvariantQueryRequest> {
    Ok(SystemsInvariantQueryRequest {
        model: systems_invariant_model(input, ctx, options)?,
        tool_policy: selected_whitebox_static_policy_for_target(target, input)?,
        thinking_level: agentic_hunter_thinking_level(input),
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
