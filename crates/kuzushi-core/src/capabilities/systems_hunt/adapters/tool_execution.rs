use super::*;

pub(crate) fn execute_trigger_synth(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let output = run_systems_trigger_synth(input, ctx, runtime)?;
    Ok(tool_json(
        format!("systems-hunt triggers: {}", output.triggers.len()),
        output,
    ))
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
    Ok(tool_json(
        format!("deep-semantic cwes: {}", output.cwes.len()),
        output,
    ))
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
