use super::*;

pub(crate) fn run_plugin_finding_adapter(
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
    let verb = spec
        .tool_name
        .split_once(':')
        .map(|(_, v)| v)
        .unwrap_or("audit");
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!("{} start · target={}", spec.tool_name, target.display()),
            )
            .emit();
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
    // Phase scope so the plugin's LLM round-trip surfaces under
    // `skill-pick · audit-loop` (or seed-gen · attack-loop · judge for
    // prompt-armor; similar shape for shinsa) in the feed.
    let _audit_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", verb, "skill-pick · audit-loop")
            .emit();
        trace.parent_scope(phase)
    });
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
    drop(_audit_scope);
    let findings = normalize_agent_json_findings(raw, &target, spec.tool_slug, max_findings)?;
    let persisted = persist_tool_findings(
        spec.tool_slug,
        &target,
        &findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                verb,
                format!("{} complete · {} findings", spec.tool_name, findings.len()),
            )
            .emit();
    }
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

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("plugin adapter structured output must be a JSON object")
    }
}

pub(crate) fn findings_schema() -> Value {
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

pub(crate) fn build_plugin_adapter_prompt(
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
