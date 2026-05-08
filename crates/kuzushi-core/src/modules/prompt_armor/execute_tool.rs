use super::*;

pub(in crate::modules) fn execute_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let handler = prompt_armor_handler(tool_name)?;
    handler(input, ctx, runtime)
}

type PromptArmorHandler = for<'a, 'b> fn(
    Value,
    &'a ToolExecutionContext<'b>,
    Option<&'a dyn AgentRuntime>,
) -> Result<Value>;

fn prompt_armor_handler(tool_name: &str) -> Result<PromptArmorHandler> {
    PROMPT_ARMOR_HANDLERS
        .iter()
        .find_map(|(name, handler)| (*name == tool_name).then_some(*handler))
        .ok_or_else(|| anyhow::anyhow!("unknown prompt-armor tool {tool_name:?}"))
}

const PROMPT_ARMOR_HANDLERS: &[(&str, PromptArmorHandler)] = &[
    ("prompt-armor:config", config_tool),
    ("prompt-armor:diff", diff_tool),
    ("prompt-armor:report", report_tool),
    ("prompt-armor:scan", scan_tool),
    ("prompt-armor:attack", attack_tool),
    ("prompt-armor:analyze", analyze_tool),
];

fn config_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let action = string_input_any(&input, &["action"]).unwrap_or_else(|| "show".to_string());
    prompt_armor_capability::config(&target, &action)
}

fn diff_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let (path_a, path_b) = diff_input_paths(&input, &target)?;
    prompt_armor_capability::diff(path_a, path_b)
}

fn diff_input_paths(
    input: &Value,
    target: &std::path::Path,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    Ok((
        required_input_path(input, target, &["runA", "run_a"], "runA")?,
        required_input_path(input, target, &["runB", "run_b"], "runB")?,
    ))
}

fn required_input_path(
    input: &Value,
    target: &std::path::Path,
    keys: &[&str],
    label: &str,
) -> Result<std::path::PathBuf> {
    let value = string_input_any(input, keys)
        .with_context(|| format!("prompt-armor:diff requires {label}"))?;
    Ok(resolve_input_path(target, &value))
}

fn report_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    _runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let out_dir = prompt_armor_capability::output_dir(&target);
    let output = string_input_any(&input, &["output"])
        .map(|path| resolve_input_path(&target, &path))
        .unwrap_or_else(|| out_dir.join("report.md"));
    prompt_armor_capability::report(&target, output)
}

fn scan_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    runtime_tool("prompt-armor:scan", input, ctx, runtime)
}

fn attack_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    runtime_tool("prompt-armor:attack", input, ctx, runtime)
}

fn analyze_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    runtime_tool("prompt-armor:analyze", input, ctx, runtime)
}

pub(in crate::modules) fn runtime_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let command = prompt_armor_capability::command_from_tool_name(tool_name);
    authorization_rejection(tool_name, command, &input)?
        .map(Ok)
        .unwrap_or_else(|| authorized_runtime_tool(tool_name, command, input, ctx, runtime))
}

fn authorized_runtime_tool(
    tool_name: &str,
    command: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    required_runtime(tool_name, runtime).and_then(|runtime| {
        runtime_inputs(tool_name, command, input, ctx).and_then(|inputs| {
            query_prompt_armor(
                &inputs.tool_name,
                &inputs.command,
                &inputs.input,
                &inputs.target,
                &inputs.plugin_root,
                runtime,
                ctx,
            )
            .and_then(|raw| runtime_tool_response(inputs, raw, ctx))
        })
    })
}

struct RuntimeInputs {
    tool_name: String,
    command: String,
    input: Value,
    target: std::path::PathBuf,
    plugin_root: std::path::PathBuf,
}

fn runtime_inputs(
    tool_name: &str,
    command: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<RuntimeInputs> {
    Ok(RuntimeInputs {
        tool_name: tool_name.to_string(),
        command: command.to_string(),
        target: resolve_tool_target(&input, ctx)?,
        plugin_root: resolve_required_plugin_root(&input, prompt_armor_plugin_spec(tool_name))?,
        input,
    })
}

fn authorization_rejection(tool_name: &str, command: &str, input: &Value) -> Result<Option<Value>> {
    let authorized = read_bool_any(input, &["authorized"])?.unwrap_or(false);
    Ok(
        (prompt_armor_capability::requires_authorization(command) && !authorized)
            .then(|| prompt_armor_capability::unauthorized_response(tool_name)),
    )
}

fn prompt_armor_plugin_spec(tool_name: &str) -> PluginAdapterSpec<'_> {
    PluginAdapterSpec {
        tool_name,
        tool_slug: "prompt-armor",
        package_name: "promptarmor-plugin",
        env_var: "KUZUSHI_PROMPT_ARMOR_PLUGIN",
        install_hint: "install promptarmor-plugin and set KUZUSHI_PROMPT_ARMOR_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    }
}

fn required_runtime<'a>(
    tool_name: &str,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))
}

fn query_prompt_armor(
    tool_name: &str,
    command: &str,
    input: &Value,
    target: &std::path::Path,
    plugin_root: &std::path::Path,
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.to_path_buf(),
            "You are Kuzushi's PromptArmor adapter. Return only JSON with findings and summary. Ground findings in source snippets when doing static analyze.".to_string(),
            prompt_armor_capability::build_prompt(command, &plugin_root, &input, &inventory),
        ),
        StructuredJsonContract::new(
            tool_name,
            "PromptArmorFindings",
            prompt_armor_capability::findings_schema(),
        ),
        prompt_armor_capability::require_json_object,
    )
}

fn runtime_tool_response(
    inputs: RuntimeInputs,
    raw: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    normalize_agent_json_findings(raw, &inputs.target, "prompt-armor", 100).and_then(|findings| {
        persist_tool_findings("prompt-armor", &inputs.target, &findings, ctx).and_then(
            |persisted| {
                ensure_prompt_armor_output_dir(&inputs.target).map(|output_dir| {
                    runtime_success_response(RuntimeSuccess {
                        tool_name: &inputs.tool_name,
                        command: &inputs.command,
                        target: &inputs.target,
                        plugin_root: &inputs.plugin_root,
                        output_dir: &output_dir,
                        findings,
                        persisted,
                    })
                })
            },
        )
    })
}

fn ensure_prompt_armor_output_dir(target: &std::path::Path) -> Result<std::path::PathBuf> {
    let output_dir = prompt_armor_capability::output_dir(target);
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;
    Ok(output_dir)
}

struct RuntimeSuccess<'a, Persisted> {
    tool_name: &'a str,
    command: &'a str,
    target: &'a std::path::Path,
    plugin_root: &'a std::path::Path,
    output_dir: &'a std::path::Path,
    findings: Vec<crate::findings::Finding>,
    persisted: Persisted,
}

fn runtime_success_response<Persisted: serde::Serialize>(
    success: RuntimeSuccess<'_, Persisted>,
) -> Value {
    json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Command: /{command}\n  Output: .prompt-armor/\n  Findings: {}",
            success.findings.len(),
            tool_name = success.tool_name,
            command = success.command,
        ),
        "data": {
            "target": success.target.display().to_string(),
            "pluginRoot": success.plugin_root.display().to_string(),
            "command": success.command,
            "outputDir": success.output_dir.display().to_string(),
            "findings": success.findings,
            "persisted": success.persisted,
        },
        "costUsd": 0.0,
    })
}
