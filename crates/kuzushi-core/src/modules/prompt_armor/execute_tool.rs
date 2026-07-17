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
    prompt_armor_capability::diff(&target, path_a, path_b)
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
    let runtime = required_runtime(tool_name, runtime)?;
    let inputs = runtime_inputs(tool_name, command, input, ctx)?;
    execute_authorized_runtime_tool(command, inputs, ctx, runtime)
}

fn execute_authorized_runtime_tool(
    command: &str,
    inputs: RuntimeInputs,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Value> {
    emit_runtime_tool_start(&inputs.tool_name, command, ctx);
    let model = resolve_tool_model(&inputs.tool_name, &inputs.input, ctx)?;
    let _runtime_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", command, "seed-gen · attack-loop · judge")
            .emit();
        trace.parent_scope(phase)
    });
    let result = run_prompt_armor_runtime(&inputs, model, ctx, runtime)?;
    drop(_runtime_scope);
    emit_runtime_tool_completion(&inputs.tool_name, command, &result, ctx);
    Ok(result)
}

fn run_prompt_armor_runtime(
    inputs: &RuntimeInputs,
    model: String,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Result<Value> {
    prompt_armor_capability::run_runtime_tool(
        prompt_armor_capability::PromptArmorRuntimeInput {
            finding_run_id: ctx.finding_run_id(),
            tool_name: &inputs.tool_name,
            command: &inputs.command,
            input: &inputs.input,
            target: &inputs.target,
            plugin_root: &inputs.plugin_root,
            model,
            runtime,
            workspace: ctx.workspace,
            findings_store: ctx.findings_store,
        },
    )
}

fn emit_runtime_tool_start(
    tool_name: &str,
    command: &str,
    ctx: &ToolExecutionContext<'_>,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("tool", command, format!("{tool_name} start"))
            .emit();
    }
}

fn emit_runtime_tool_completion(
    tool_name: &str,
    command: &str,
    result: &Value,
    ctx: &ToolExecutionContext<'_>,
) {
    if let Some(trace) = ctx.trace {
        let count = prompt_armor_finding_count(result);
        let _ = trace
            .step(
                "done",
                command,
                format!("{tool_name} complete · {count} findings"),
            )
            .emit();
    }
}

fn prompt_armor_finding_count(result: &Value) -> usize {
    result
        .pointer("/data/findings")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
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
        package_name: "promptarmor-plugin",
        env_var: "KUZUSHI_PROMPT_ARMOR_PLUGIN",
        install_hint: "install promptarmor-plugin and set KUZUSHI_PROMPT_ARMOR_PLUGIN",
    }
}

fn required_runtime<'a>(
    tool_name: &str,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(format!(
        "{tool_name} requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies."
    ))
}
