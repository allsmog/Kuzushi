use super::*;

pub(crate) fn execute_trigger_synth(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let output = run_systems_trigger_synth_with_cost(input, ctx, runtime)?;
    let mut result = tool_json(
        format!("systems-hunt triggers: {}", output.value.triggers.len()),
        &output.value,
    );
    crate::module_result::apply_runtime_cost_report(&mut result, output.cost_report()?);
    Ok(result)
}

pub(crate) fn execute_systems_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_systems_hunt_report(input, ctx, runtime)?.to_tool_json())
}

pub(crate) fn execute_deep_semantic_cwe(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let output = run_deep_semantic_cwe_select(input, ctx, runtime)?;
    let mut result = tool_json(
        format!("deep-semantic cwes: {}", output.cwes.len()),
        &output,
    );
    let observed =
        crate::runtime::RuntimeCost::from_usd(output.cost_usd, "deep-semantic CWE selection cost")?;
    let cost = if output.cost_usd_exact {
        crate::runtime::RuntimeCostReport::known(observed)
    } else {
        crate::runtime::RuntimeCostReport::incomplete(observed)
    };
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

pub(crate) fn execute_deep_semantic_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    Ok(run_deep_semantic_hunt_report(input, ctx, runtime)?.to_tool_json())
}

pub(crate) fn tool_json<T: Serialize>(output: String, data: T) -> Value {
    let mut result =
        crate::module_result::completed_output_result(output.clone(), output, json!(data));
    result["costUsd"] = json!(0.0);
    result
}

pub fn gather_surfaces(target: &Path, input: &Value) -> Result<SystemsContextOutput> {
    if !target.is_dir() {
        anyhow::bail!(
            "systems-hunt: target is not a directory: {}",
            target.display()
        );
    }
    let options = SystemsHuntInput::from_tool_input(input)?;
    gather_systems_context(target, &options)
}
