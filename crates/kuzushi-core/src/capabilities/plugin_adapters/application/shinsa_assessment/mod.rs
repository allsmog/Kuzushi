use super::run_plugin_finding_adapter::{findings_schema, require_json_object};
use super::*;

mod artifacts;
mod mode;
mod prompt;
mod response;

pub(crate) fn run_shinsa_assessment(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let run = prepare_shinsa_assessment(tool_name, input, ctx, runtime)?;
    let raw = query_shinsa_with_scope(&run, ctx)?;
    let findings = normalize_agent_json_findings(raw.clone(), &run.target, "shinsa", 100)?;
    let persisted = persist_shinsa_findings(&run, &findings, ctx)?;
    let artifacts = write_shinsa_assessment_artifacts(&run, findings.len(), &raw)?;
    emit_shinsa_done(ctx, &run, findings.len());
    Ok(shinsa_assessment_response(
        &run, artifacts, findings, persisted,
    ))
}

struct ShinsaAssessmentRun<'tool, 'runtime> {
    tool_name: &'tool str,
    input: Value,
    target: PathBuf,
    verb: &'tool str,
    plugin_root: PathBuf,
    runtime: &'runtime dyn AgentRuntime,
    model: String,
    mode: &'static str,
    output_dir: String,
    inventory: Vec<(String, String)>,
}

fn prepare_shinsa_assessment<'tool, 'runtime>(
    tool_name: &'tool str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'runtime dyn AgentRuntime>,
) -> Result<ShinsaAssessmentRun<'tool, 'runtime>> {
    let target = resolve_tool_target(&input, ctx)?;
    let verb = shinsa_assessment_verb(tool_name);
    emit_shinsa_start(ctx, tool_name, verb, &target);
    let execution = resolve_shinsa_execution(tool_name, &input, ctx, runtime)?;
    artifacts::prepare_shinsa_output_root(&target, &execution.output_dir)?;
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    Ok(ShinsaAssessmentRun {
        tool_name,
        input,
        target,
        verb,
        plugin_root: execution.plugin_root,
        runtime: execution.runtime,
        model: execution.model,
        mode: execution.mode,
        output_dir: execution.output_dir,
        inventory,
    })
}

fn shinsa_assessment_verb(tool_name: &str) -> &str {
    tool_name.split_once(':').map(|(_, v)| v).unwrap_or("scan")
}

struct ShinsaExecution<'runtime> {
    plugin_root: PathBuf,
    runtime: &'runtime dyn AgentRuntime,
    model: String,
    mode: &'static str,
    output_dir: String,
}

fn resolve_shinsa_execution<'runtime>(
    tool_name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'runtime dyn AgentRuntime>,
) -> Result<ShinsaExecution<'runtime>> {
    let plugin_root = resolve_required_plugin_root(input, shinsa_plugin_spec(tool_name))?;
    let runtime = require_shinsa_runtime(tool_name, runtime)?;
    let model = resolve_tool_model(tool_name, input, ctx)?;
    Ok(ShinsaExecution {
        plugin_root,
        runtime,
        model,
        mode: mode::shinsa_mode(tool_name, input),
        output_dir: shinsa_output_dir(input),
    })
}

fn require_shinsa_runtime<'runtime>(
    tool_name: &str,
    runtime: Option<&'runtime dyn AgentRuntime>,
) -> Result<&'runtime dyn AgentRuntime> {
    runtime.context(format!(
        "{tool_name} requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies."
    ))
}

fn shinsa_output_dir(input: &Value) -> String {
    string_input_any(input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| "shinsa-output".to_string())
}

fn query_shinsa_with_scope(
    run: &ShinsaAssessmentRun<'_, '_>,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let _control_scope = begin_shinsa_control_scope(ctx, run.verb);
    let raw = query_shinsa_report(
        run.runtime,
        run.model.clone(),
        &run.target,
        prompt::ShinsaPromptInput {
            tool_name: run.tool_name,
            mode: run.mode,
            output_dir: &run.output_dir,
            plugin_root: &run.plugin_root,
            input: &run.input,
            inventory: &run.inventory,
        },
    )?;
    drop(_control_scope);
    Ok(raw)
}

fn begin_shinsa_control_scope(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step("reasoning", verb, "framework-load · control-eval")
            .emit();
        trace.parent_scope(phase)
    })
}

fn persist_shinsa_findings(
    run: &ShinsaAssessmentRun<'_, '_>,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<GenericPersistedRun>> {
    persist_tool_findings(
        "shinsa",
        &run.target,
        findings,
        ctx.workspace,
        ctx.findings_store,
    )
}

fn write_shinsa_assessment_artifacts(
    run: &ShinsaAssessmentRun<'_, '_>,
    finding_count: usize,
    raw: &Value,
) -> Result<artifacts::ShinsaArtifacts> {
    artifacts::write_shinsa_artifacts(&run.target, &run.output_dir, run.mode, finding_count, raw)
}

fn shinsa_assessment_response(
    run: &ShinsaAssessmentRun<'_, '_>,
    artifacts: artifacts::ShinsaArtifacts,
    findings: Vec<Finding>,
    persisted: Option<GenericPersistedRun>,
) -> Value {
    response::shinsa_response(
        run.tool_name,
        &run.target,
        run.mode,
        &run.plugin_root,
        &run.output_dir,
        artifacts,
        findings,
        persisted,
    )
}

fn emit_shinsa_start(ctx: &ToolExecutionContext<'_>, tool_name: &str, verb: &str, target: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!("{tool_name} start · target={}", target.display()),
            )
            .emit();
    }
}

fn emit_shinsa_done(
    ctx: &ToolExecutionContext<'_>,
    run: &ShinsaAssessmentRun<'_, '_>,
    finding_count: usize,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                run.verb,
                format!("{} complete · {finding_count} findings", run.tool_name),
            )
            .emit();
    }
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
