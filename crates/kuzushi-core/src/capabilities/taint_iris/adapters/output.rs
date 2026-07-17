use super::*;

pub(crate) fn run_taint_cwe_select(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let model = optional_nonempty_string(&input, "model")?.or_else(|| ctx.config.model.clone());
    let cwes = run_taint_cwe_select_value(&input, &target, runtime, model.as_deref())?;
    let summary = format!(
        "pipeline:taint-cwe-select selected {} CWE class{}",
        cwes.value.len(),
        if cwes.value.len() == 1 { "" } else { "es" }
    );
    let data = json!({
        "target": target.display().to_string(),
        "cwes": cwes.value,
    });
    let mut result = crate::module_result::completed_output_result(
        summary.clone(),
        summary,
        data,
    );
    crate::module_result::apply_runtime_cost_report(&mut result, cwes.cost_report()?);
    Ok(result)
}
