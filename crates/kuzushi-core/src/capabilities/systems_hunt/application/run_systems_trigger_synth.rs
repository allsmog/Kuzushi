use super::*;

#[cfg(test)]
pub(crate) fn run_systems_trigger_synth(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<SystemsTriggerOutput> {
    Ok(run_systems_trigger_synth_with_cost(input, ctx, runtime)?.value)
}

pub(crate) fn run_systems_trigger_synth_with_cost(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<CostedStructuredJson<SystemsTriggerOutput>> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let context = systems_context_from_input_or_gather(input, &target, &options)?;
    if systems_context_is_empty(&context) {
        return Ok(empty_systems_trigger_synthesis());
    }
    let request = SystemsTriggerSynthesisRequest {
        input,
        runtime: required_systems_runtime(runtime, "systems-hunt:systems-trigger-synth")?,
        model: resolve_model("systems-hunt:systems-trigger-synth", input, ctx, &options)?,
        agent_tool_policy: try_whitebox_static_policy_for_target(&target)?,
        thinking_level: agentic_hunter_thinking_level(input),
        target,
        context,
        options,
    };
    let llm_scope = open_systems_trigger_scope(ctx);
    let result = request.execute();
    drop(llm_scope);
    result
}

struct SystemsTriggerSynthesisRequest<'a> {
    input: &'a Value,
    runtime: &'a dyn AgentRuntime,
    model: String,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: String,
    target: PathBuf,
    context: SystemsContextOutput,
    options: SystemsHuntInput,
}

impl SystemsTriggerSynthesisRequest<'_> {
    fn execute(self) -> Result<CostedStructuredJson<SystemsTriggerOutput>> {
        let invariant_output = systems_invariants_from_input_or_query_with_cost(
            self.input,
            self.runtime,
            &self.model,
            &self.target,
            &self.context,
            &self.options,
            self.agent_tool_policy.clone(),
            &self.thinking_level,
        )?;
        let triggers = query_systems_triggers_with_cost(
            self.runtime,
            &self.model,
            &self.target,
            &self.context,
            &invariant_output.value,
            &self.options,
            self.agent_tool_policy,
            &self.thinking_level,
        )?;
        let cost = invariant_output.cost_report()?.checked_add(
            triggers.cost_report()?,
            "systems trigger synthesis invariant plus trigger cost",
        )?;
        Ok(CostedStructuredJson::from_cost_report(triggers.value, cost))
    }
}

fn empty_systems_trigger_synthesis() -> CostedStructuredJson<SystemsTriggerOutput> {
    CostedStructuredJson::from_cost_report(
        SystemsTriggerOutput {
            triggers: Vec::new(),
        },
        crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
    )
}

fn open_systems_trigger_scope(
    ctx: &ToolExecutionContext<'_>,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                "systems-trigger-synth",
                "invariant + trigger synthesis",
            )
            .emit();
        trace.parent_scope(phase)
    })
}

pub(crate) fn systems_context_from_input_or_gather(
    input: &Value,
    target: &Path,
    options: &SystemsHuntInput,
) -> Result<SystemsContextOutput> {
    match context_from_input(input).transpose()? {
        Some(context) => Ok(context),
        None => gather_systems_context(target, options)
            .context("could not gather systems-hunt context from the target"),
    }
}

pub(crate) fn systems_context_is_empty(context: &SystemsContextOutput) -> bool {
    context.surfaces.is_empty()
}

pub(crate) fn required_systems_runtime<'a>(
    runtime: Option<&'a dyn AgentRuntime>,
    tool: &str,
) -> Result<&'a dyn AgentRuntime> {
    runtime.with_context(|| format!(
        "{tool} requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies."
    ))
}

pub(crate) fn systems_invariants_from_input_or_query_with_cost(
    input: &Value,
    runtime: &dyn AgentRuntime,
    model: &str,
    target: &Path,
    context: &SystemsContextOutput,
    options: &SystemsHuntInput,
    agent_tool_policy: AgentToolPolicy,
    thinking_level: &str,
) -> Result<CostedStructuredJson<SystemsInvariantOutput>> {
    match invariants_from_input(input).transpose()? {
        Some(output) => Ok(CostedStructuredJson {
            value: output,
            cost_usd: 0.0,
            cost_usd_exact: true,
        }),
        None => query_systems_invariants_with_cost(
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
