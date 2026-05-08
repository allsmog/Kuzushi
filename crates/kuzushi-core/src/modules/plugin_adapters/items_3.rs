use super::prelude::*;
use super::*;

pub(in crate::modules) fn run_plugin_finding_adapter(
    spec: PluginAdapterSpec<'_>,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "{} target is not a directory: {}",
            spec.tool_name,
            target.display()
        );
    }
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
        spec.tool_name
    ))?;
    let model = resolve_tool_model(spec.tool_name, &input, ctx)?;
    let max_findings =
        positive_usize_input(&input, &["maxFindings", "max_findings"], "maxFindings")?
            .unwrap_or(50)
            .min(200);
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            format!(
                "You are Kuzushi's {} pi-agent-core adapter. Return only JSON matching {{\"findings\":[{{\"ruleId\":\"...\",\"filePath\":\"relative/path\",\"startLine\":1,\"severity\":\"critical|high|medium|low|info\",\"message\":\"evidence-backed finding\",\"evidence\":\"source-grounded proof\"}}]}}.",
                spec.tool_name
            ),
            build_plugin_adapter_prompt(spec, &target, &plugin_root, &input, &inventory),
        ),
        StructuredJsonContract::new(spec.tool_name, "PluginAdapterFindings", findings_schema()),
        require_json_object,
    )?;
    let findings = normalize_agent_json_findings(raw, &target, spec.tool_slug, max_findings)?;
    let persisted = persist_tool_findings(spec.tool_slug, &target, &findings, ctx)?;
    Ok(json!({
        "ok": true,
        "output": render_generic_findings_output(spec.tool_name, &target, &findings, &persisted),
        "data": {
            "target": target.display().to_string(),
            "pluginRoot": plugin_root.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

pub(in crate::modules) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("plugin adapter structured output must be a JSON object")
    }
}

pub(in crate::modules) fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "summary": {"type": "string"},
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

pub(in crate::modules) fn build_plugin_adapter_prompt(
    spec: PluginAdapterSpec<'_>,
    target: &Path,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        spec.prompt_title.to_string(),
        format!("Target: {}", target.display()),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "Use only the provided repository snippets; do not claim runtime exploitability."
            .to_string(),
    ];
    if spec.allow_skill_filter {
        if let Some(skills) = string_array_or_csv_input(input, &["skills"]) {
            lines.push(format!("Requested skills: {}", skills.join(", ")));
        }
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}
