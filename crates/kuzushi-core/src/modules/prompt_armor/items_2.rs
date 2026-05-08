use super::prelude::*;
use super::*;

pub(in crate::modules) fn execute_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match tool_name {
        "prompt-armor:config" => config(input, ctx),
        "prompt-armor:diff" => diff(input, ctx),
        "prompt-armor:report" => report(input, ctx),
        "prompt-armor:scan" | "prompt-armor:attack" | "prompt-armor:analyze" => {
            runtime_tool(tool_name, input, ctx, runtime)
        }
        _ => anyhow::bail!("unknown prompt-armor tool {tool_name:?}"),
    }
}

pub(in crate::modules) fn runtime_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let command = tool_name.trim_start_matches("prompt-armor:");
    if matches!(command, "scan" | "attack")
        && !read_bool_any(&input, &["authorized"])?.unwrap_or(false)
    {
        return Ok(json!({
            "ok": false,
            "output": format!("{tool_name} refuses to run: pass authorized=true to confirm you have authorization to test the target endpoint. This command can generate real traffic."),
        }));
    }
    let target = resolve_tool_target(&input, ctx)?;
    let spec = PluginAdapterSpec {
        tool_name,
        tool_slug: "prompt-armor",
        package_name: "promptarmor-plugin",
        env_var: "KUZUSHI_PROMPT_ARMOR_PLUGIN",
        install_hint: "install promptarmor-plugin and set KUZUSHI_PROMPT_ARMOR_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))?;
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            "You are Kuzushi's PromptArmor adapter. Return only JSON with findings and summary. Ground findings in source snippets when doing static analyze.".to_string(),
            build_prompt(command, &plugin_root, &input, &inventory),
        ),
        StructuredJsonContract::new(tool_name, "PromptArmorFindings", findings_schema()),
        require_json_object,
    )?;
    let findings = normalize_agent_json_findings(raw, &target, "prompt-armor", 100)?;
    let persisted = persist_tool_findings("prompt-armor", &target, &findings, ctx)?;
    let output_dir = target.join(".prompt-armor");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Command: /{command}\n  Output: .prompt-armor/\n  Findings: {}",
            findings.len()
        ),
        "data": {
            "target": target.display().to_string(),
            "pluginRoot": plugin_root.display().to_string(),
            "command": command,
            "outputDir": output_dir.display().to_string(),
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
        anyhow::bail!("prompt-armor structured output must be a JSON object")
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
