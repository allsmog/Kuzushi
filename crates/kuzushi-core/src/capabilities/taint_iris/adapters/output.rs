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
    let output = selection_output(&summary, &cwes.value);
    let data = json!({
        "target": target.display().to_string(),
        "cwes": cwes.value,
    });
    let mut result = crate::module_result::completed_output_result(summary, output, data);
    crate::module_result::apply_runtime_cost_report(&mut result, cwes.cost_report()?);
    Ok(result)
}

fn selection_output(summary: &str, classes: &[TaintCweSelection]) -> String {
    let mut lines = vec![summary.to_string()];
    lines.extend(
        classes
            .iter()
            .map(|class| format!("  {} · {}\n    {}", class.id, class.name, class.reason)),
    );
    lines.push(
        "Selected classes are planning guidance. No scan jobs or findings were created.".into(),
    );
    lines.join("\n")
}
