use super::*;

pub(crate) fn run_plugin_finding_adapter(
    spec: PluginAdapterSpec<'_>,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let run = prepare_plugin_finding_run(spec, &input, ctx, runtime)?;
    let findings = run_plugin_finding_query(&run, &input, ctx)?;
    let persisted = persist_plugin_adapter_findings(&run, &findings.value, ctx)?;
    emit_plugin_adapter_done(ctx, &run, findings.value.len());
    let cost = findings.cost_report()?;
    Ok(plugin_adapter_response(
        &run,
        findings.value,
        persisted,
        cost,
    ))
}

struct PluginFindingRun<'spec, 'runtime> {
    spec: PluginAdapterSpec<'spec>,
    target: PathBuf,
    verb: &'spec str,
    plugin_root: PathBuf,
    runtime: &'runtime dyn AgentRuntime,
    model: String,
    max_findings: usize,
    inventory: Vec<(String, String)>,
}

fn prepare_plugin_finding_run<'spec, 'runtime>(
    spec: PluginAdapterSpec<'spec>,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'runtime dyn AgentRuntime>,
) -> Result<PluginFindingRun<'spec, 'runtime>> {
    let target = resolve_tool_target(input, ctx)?;
    ensure_plugin_adapter_target_dir(spec, &target)?;
    let verb = plugin_adapter_verb(spec);
    emit_plugin_adapter_start(ctx, spec, verb, &target);
    let execution = resolve_plugin_adapter_execution(spec, input, ctx, runtime)?;
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    Ok(PluginFindingRun {
        spec,
        target,
        verb,
        plugin_root: execution.plugin_root,
        runtime: execution.runtime,
        model: execution.model,
        max_findings: execution.max_findings,
        inventory,
    })
}

fn ensure_plugin_adapter_target_dir(spec: PluginAdapterSpec<'_>, target: &Path) -> Result<()> {
    if target.is_dir() {
        return Ok(());
    }
    anyhow::bail!(
        "{} target is not a directory: {}",
        spec.tool_name,
        target.display()
    );
}

fn plugin_adapter_verb<'a>(spec: PluginAdapterSpec<'a>) -> &'a str {
    spec.tool_name
        .split_once(':')
        .map(|(_, verb)| verb)
        .unwrap_or("audit")
}

fn emit_plugin_adapter_start(
    ctx: &ToolExecutionContext<'_>,
    spec: PluginAdapterSpec<'_>,
    verb: &str,
    target: &Path,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!("{} start · target={}", spec.tool_name, target.display()),
            )
            .emit();
    }
}

struct PluginAdapterExecution<'a> {
    plugin_root: PathBuf,
    runtime: &'a dyn AgentRuntime,
    model: String,
    max_findings: usize,
}

fn resolve_plugin_adapter_execution<'a>(
    spec: PluginAdapterSpec<'_>,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<PluginAdapterExecution<'a>> {
    let plugin_root = resolve_required_plugin_root(input, spec)?;
    let runtime = require_plugin_adapter_runtime(spec, runtime)?;
    let model = resolve_tool_model(spec.tool_name, input, ctx)?;
    let max_findings = plugin_adapter_max_findings(input)?;
    Ok(PluginAdapterExecution {
        plugin_root,
        runtime,
        model,
        max_findings,
    })
}

fn require_plugin_adapter_runtime<'a>(
    spec: PluginAdapterSpec<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.context(format!(
        "{} requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
        spec.tool_name
    ))
}

fn plugin_adapter_max_findings(input: &Value) -> Result<usize> {
    Ok(
        positive_usize_input(input, &["maxFindings", "max_findings"], "maxFindings")?
            .unwrap_or(50)
            .min(200),
    )
}

fn run_plugin_finding_query(
    run: &PluginFindingRun<'_, '_>,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    let raw = query_plugin_adapter(run, input, ctx)?;
    Ok(CostedStructuredJson {
        value: normalize_agent_json_findings(
            raw.value,
            &run.target,
            run.spec.tool_slug,
            run.max_findings,
        )?,
        cost_usd: raw.cost_usd,
        cost_usd_exact: raw.cost_usd_exact,
        estimated_cost_usd: raw.estimated_cost_usd,
    })
}

fn query_plugin_adapter(
    run: &PluginFindingRun<'_, '_>,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<CostedStructuredJson<Value>> {
    // Phase scope so the plugin's LLM round-trip surfaces under
    // `skill-pick · audit-loop` (or seed-gen · attack-loop · judge for
    // prompt-armor; similar shape for shinsa) in the feed.
    let _audit_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", run.verb, "skill-pick · audit-loop")
            .emit();
        trace.parent_scope(phase)
    });
    let raw = query_required_structured_json_with_cost(
        run.runtime,
        AgentQueryRequest::new(
            run.model.clone(),
            run.target.clone(),
            format!(
                "You are Kuzushi's {} LangGraph adapter. Return only JSON matching {{\"findings\":[{{\"ruleId\":\"...\",\"filePath\":\"relative/path\",\"startLine\":1,\"severity\":\"critical|high|medium|low|info\",\"message\":\"evidence-backed finding\",\"evidence\":\"source-grounded proof\"}}]}}.",
                run.spec.tool_name
            ),
            build_plugin_adapter_prompt(
                run.spec,
                &run.target,
                &run.plugin_root,
                input,
                &run.inventory,
            ),
        ),
        StructuredJsonContract::new(
            run.spec.tool_name,
            "PluginAdapterFindings",
            findings_schema(),
        ),
        require_json_object,
    )?;
    drop(_audit_scope);
    Ok(raw)
}

fn persist_plugin_adapter_findings(
    run: &PluginFindingRun<'_, '_>,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    persist_tool_findings(ctx, &run.target, findings)
}

fn emit_plugin_adapter_done(
    ctx: &ToolExecutionContext<'_>,
    run: &PluginFindingRun<'_, '_>,
    finding_count: usize,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                run.verb,
                format!("{} complete · {finding_count} findings", run.spec.tool_name),
            )
            .emit();
    }
}

fn plugin_adapter_response(
    run: &PluginFindingRun<'_, '_>,
    findings: Vec<Finding>,
    persisted: Option<GenericPersistedRun>,
    cost: crate::runtime::RuntimeCostReport,
) -> Value {
    let output = render_generic_findings_output(
        run.spec.tool_name,
        &run.target,
        &findings,
        &persisted,
    );
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": run.target.display().to_string(),
            "pluginRoot": run.plugin_root.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        }),
    );
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
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
