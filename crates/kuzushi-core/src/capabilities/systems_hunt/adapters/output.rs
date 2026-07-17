use super::*;

impl SystemsHuntReport {
    pub fn output(&self) -> String {
        let mut lines = vec![format!(
            "systems-hunt: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];
        if let Some(persisted) = &self.persisted {
            lines.push(format!(
                "  Persisted run: {} ({})",
                persisted.run_id, persisted.findings_db
            ));
        }
        for finding in self.findings.iter().take(10) {
            lines.push(format!(
                "  - {} - {} - {}:{}",
                finding.severity.as_str(),
                finding.rule_id,
                finding.file_path,
                finding.start_line
            ));
        }
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        let report_output = self.output();
        let mut output = crate::module_result::completed_output_result(
            report_output.clone(),
            report_output,
            json!(self),
        );
        let observed =
            crate::runtime::RuntimeCost::from_usd(self.cost_usd, "systems-hunt report cost")
                .expect("systems-hunt validates runtime cost before report construction");
        let cost = if self.cost_usd_exact {
            crate::runtime::RuntimeCostReport::known(observed)
        } else {
            crate::runtime::RuntimeCostReport::incomplete(observed)
        };
        crate::module_result::apply_runtime_cost_report(&mut output, cost);
        output
    }
}

pub fn execute_systems_hunt_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let input = &input;
    match name {
        "systems-hunt:systems-context-gatherer" => execute_context_gatherer(input, ctx),
        "systems-hunt:systems-invariant-extract" => execute_invariant_extract(input, ctx, runtime),
        "systems-hunt:systems-trigger-synth" => execute_trigger_synth(input, ctx, runtime),
        "systems-hunt:systems-hunt" => execute_systems_report(input, ctx, runtime),
        "systems-hunt:deep-semantic-cwe-select" => execute_deep_semantic_cwe(input, ctx, runtime),
        "systems-hunt:deep-semantic-hunt" => execute_deep_semantic_report(input, ctx, runtime),
        other => anyhow::bail!("unknown systems-hunt tool {other:?}"),
    }
}

pub(crate) fn execute_context_gatherer(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_target(input, ctx)?;
    let options = SystemsHuntInput::from_tool_input(input)?;
    let output = gather_systems_context(&target, &options)?;
    Ok(tool_json(
        format!("systems-hunt context: {} surface(s)", output.surfaces.len()),
        output,
    ))
}

pub(crate) fn execute_invariant_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let output = run_systems_invariant_extract_with_cost(input, ctx, runtime)?;
    let mut result = tool_json(
        format!("systems-hunt invariants: {}", output.value.invariants.len()),
        &output.value,
    );
    crate::module_result::apply_runtime_cost_report(&mut result, output.cost_report()?);
    Ok(result)
}
