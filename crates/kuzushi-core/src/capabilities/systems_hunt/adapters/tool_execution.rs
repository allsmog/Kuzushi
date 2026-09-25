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
    match run_systems_hunt_report(input, ctx, runtime) {
        Ok(report) => Ok(report.to_tool_json()),
        Err(error) => not_applicable_result(error),
    }
}

/// Only the typed not-applicable refusal becomes a `skipped` result; every
/// other error still fails the tool.
fn not_applicable_result(error: anyhow::Error) -> Result<Value> {
    let Some(reason) = error.downcast_ref::<SystemsHuntNotApplicable>() else {
        return Err(error);
    };
    let summary = reason.to_string();
    Ok(crate::module_result::skipped_output_result(
        summary.clone(),
        summary,
        Vec::new(),
        serde_json::json!({"notApplicable": true}),
    ))
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

#[cfg(test)]
mod not_applicable_tests {
    use super::*;

    #[test]
    fn only_the_typed_refusal_becomes_a_skip() {
        let skipped = not_applicable_result(
            SystemsHuntNotApplicable {
                target: "/t".to_string(),
            }
            .into(),
        )
        .unwrap();
        assert_eq!(skipped["status"], "skipped");
        assert_eq!(skipped["data"]["notApplicable"], true);
        assert!(skipped["summary"].as_str().unwrap().contains("does not apply"));

        let failure = not_applicable_result(anyhow::anyhow!("model refused"));
        assert!(failure.is_err());
    }
}
