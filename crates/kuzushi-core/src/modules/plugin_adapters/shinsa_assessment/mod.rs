use super::run_plugin_finding_adapter::require_json_object;
use super::*;

mod artifacts;
mod mode;
mod prompt;
mod response;

pub(in crate::modules) fn run_shinsa_assessment(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let verb = tool_name.split_once(':').map(|(_, v)| v).unwrap_or("scan");
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!("{tool_name} start · target={}", target.display()),
            )
            .emit();
    }
    let plugin_root = resolve_required_plugin_root(&input, shinsa_plugin_spec(tool_name))?;
    let runtime = runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))?;
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let mode = mode::shinsa_mode(tool_name);
    let output_dir = string_input_any(&input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| "shinsa-output".to_string());
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;

    // Phase scope so the shinsa LLM round-trip surfaces under
    // `framework-load · control-eval` in the feed.
    let _control_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", verb, "framework-load · control-eval")
            .emit();
        trace.parent_scope(phase)
    });
    let raw = query_shinsa_report(
        runtime,
        model,
        &target,
        prompt::ShinsaPromptInput {
            tool_name,
            mode,
            output_dir: &output_dir,
            plugin_root: &plugin_root,
            input: &input,
            inventory: &inventory,
        },
    )?;
    drop(_control_scope);
    let findings = normalize_agent_json_findings(raw.clone(), &target, "shinsa", 100)?;
    let persisted = persist_tool_findings("shinsa", &target, &findings, ctx)?;
    let artifacts =
        artifacts::write_shinsa_artifacts(&target, &output_dir, mode, findings.len(), &raw)?;

    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                verb,
                format!("{tool_name} complete · {} findings", findings.len()),
            )
            .emit();
    }
    Ok(response::shinsa_response(
        tool_name,
        &target,
        mode,
        &plugin_root,
        &output_dir,
        artifacts,
        findings,
        persisted,
    ))
}

fn shinsa_plugin_spec(tool_name: &str) -> PluginAdapterSpec<'_> {
    PluginAdapterSpec {
        tool_name,
        tool_slug: "shinsa",
        package_name: "shinsa-plugin",
        env_var: "KUZUSHI_SHINSA_PLUGIN",
        install_hint: "install shinsa-plugin and set KUZUSHI_SHINSA_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    }
}

fn query_shinsa_report(
    runtime: &dyn AgentRuntime,
    model: String,
    target: &Path,
    prompt: prompt::ShinsaPromptInput<'_>,
) -> Result<Value> {
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.to_path_buf(),
            "You are Kuzushi's Shinsa compliance adapter. Return only JSON with summary, findings, controls, and maturity.".to_string(),
            prompt::build_shinsa_prompt(&prompt),
        ),
        StructuredJsonContract::new(prompt.tool_name, "ShinsaReport", findings_schema()),
        require_json_object,
    )
}
