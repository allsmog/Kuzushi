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
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
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
    let output = run_systems_invariant_extract(input, ctx, runtime)?;
    Ok(tool_json(
        format!("systems-hunt invariants: {}", output.invariants.len()),
        output,
    ))
}
