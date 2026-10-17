use super::*;

#[cfg(test)]
pub(crate) fn run_deep_semantic_cwe_select(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<DeepSemanticCweOutput> {
    let options = SystemsHuntInput::from_tool_input(input)?;
    let mut projected = input.clone();
    projected
        .as_object_mut()
        .context("Legacy CWE input must be an object")?
        .insert(
            "SYSTEMS_DEEP_CWE_PROMPT".into(),
            json!(options.deep_semantic_cwe_system_prompt),
        );
    super::cwe_proposal::legacy_select(&projected, ctx, runtime)
}

#[cfg(test)]
pub(crate) fn selected_deep_semantic_cwes(
    input: &Value,
    _ctx: &ToolExecutionContext<'_>,
    _runtime: &dyn AgentRuntime,
    options: &SystemsHuntInput,
) -> Result<CostedStructuredJson<Vec<DeepSemanticCweSelection>>> {
    let mut explicit = input.clone();
    explicit["maxCweClasses"] = json!(options.max_cwe_classes);
    Ok(CostedStructuredJson {
        value: super::deep_discovery::explicit_classes(&explicit)?,
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    })
}
